
# SSL Related Libraries -- this creates the object to parse certificates however python users may not have the cryptography.io library so we catch this as an error
import ssl
import socket

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    pass
from datetime import datetime,time

#FastAPI and Pydantic Related Libraries
from fastapi import FastAPI
from pydantic import BaseModel,Field
from typing import List

#APScheduler Related Libraries
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore

import logging

#Global Variables

app = FastAPI(title="Scheduling X509 Certificate Checks with FastAPI and APSCheduler",version="2020.11.1",description="An Example of Scheduling SSL Certificate Checks with FastAPI and Pythons Standard SSL and Cryptography.io Libraries")
Schedule = None
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.on_event("startup")
async def load_schedule_or_create_blank():
    """
    Instatialise the Schedule Object as a Global Param and also load existing Schedules from SQLite
    This allows for persistent schedules across server restarts. 
    """
    global Schedule
    try:
        jobstores = {
            'default': SQLAlchemyJobStore(url='sqlite:///jobs.sqlite')
        }
        Schedule = AsyncIOScheduler(jobstores=jobstores)
        Schedule.start()
        logger.info("Created Schedule Object")   
    except:    
        logger.error("Unable to Create Schedule Object")       


@app.on_event("shutdown")
async def pickle_schedule():
    """
    An Attempt at Shutting down the schedule to avoid orphan jobs
    """
    global Schedule
    Schedule.shutdown()
    logger.info("Disabled Schedule")
    

class CertificateCheckResponse(BaseModel):
    end_date:datetime=Field(title="End Date in ISO-8601 Format",description="End Date in ISO-8601 Format")
    time_to_expiry:int=Field(title="Number of Days Till Expiry",description="Number of Days Till Expiry")
    subject:str=Field(title="Subject of Certificate",description="Subject of Certificate")
    serial:int=Field(title="Serial of the Certificate",description="Serial of the Certificate")
    class Config:
        schema_extra = {
             'example': {
                "end_date": "2021-01-12T18:08:34",
                "time_to_expiry": 64,
                "subject": "<X509Name object '/C=US/ST=California/L=Mountain View/O=Google LLC/CN=www.google.com'>",
                "serial": 24071124635451757
            }
        }

class CurrentScheduledJob(BaseModel):
    job_id:str=Field(title="The Job ID in APScheduler",description="The Job ID in APScheduler")
    run_frequency:str=Field(title="The Job Interval in APScheduler",description="The Job Interval in APScheduler")
    next_run:str=Field(title="Next Scheduled Run for the Job",description="Next Scheduled Run for the Job")
    class Config:
        schema_extra = {
             'example':   {
                "job_id": "www.google.com",
                "run_frequency": "interval[0:05:00]",
                "next_run": "2020-11-10 22:12:09.397935+10:00"
            }
        }

class CurrentScheduledJobsResponse(BaseModel):
    jobs:List[CurrentScheduledJob]       

class JobCreateDeleteResponse(BaseModel):
    scheduled:bool=Field(title="Whether the job was scheduler or not",description="Whether the job was scheduler or not")
    job_id:str=Field(title="The Job ID in APScheduler",description="The Job ID in APScheduler")
    class Config:
        schema_extra = {
                    'example':   {
                    "scheduled": True,
                    "job_id": "www.google.com"
                    }
        }



@app.post("/x509/check_host_certificate/",response_model=CertificateCheckResponse,tags=["x509 checks"])
def check_host_certificate(host="www.google.com"):
    """
    Given a Hostname will establish a RAW SSL Socket and get the peer certificate.

    The certificate is then parsed and then certain fields are brought back

    If cryptography.io is not present then dummy data is bought back

    """
    port = 443
    conn = ssl.create_connection((host, port))
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sock = context.wrap_socket(conn, server_hostname=host)
    raw_pem_cert = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))

    try:
        parsed_cert = x509.load_pem_x509_certificate(raw_pem_cert.encode("UTF-8"), default_backend())
        end_date = parsed_cert.not_valid_after
        time_to_expiry = (end_date - datetime.now()).days
        subject = str(parsed_cert.subject)
        serial = parsed_cert.serial_number
        logger.info("Parsed Certificate Sucessfully Using Cryptography.io")
        logger.info(subject)
    except:
        end_date = datetime.now()
        time_to_expiry = 0
        subject = ""
        serial = 0
        logger.warn("Failed to Parse Certificate Using Cryptography.io -- using Placeholder Variables")
    return {"end_date":end_date,"time_to_expiry":time_to_expiry,"subject":subject,"serial":serial}

@app.get("/schedule/show_schedules/",response_model=CurrentScheduledJobsResponse,tags=["schedule"])
async def get_scheduled_syncs():
    """
    Will provide a list of currently Scheduled Tasks

    """
    schedules = []
    for job in Schedule.get_jobs():
        schedules.append({"job_id": str(job.id), "run_frequency": str(job.trigger), "next_run": str(job.next_run_time)})
    return {"jobs":schedules}

@app.post("/schedule/host_ssl_check/",response_model=JobCreateDeleteResponse,tags=["schedule"])
async def add_ssl_check_to_scheduler(time_in_seconds:int=60,host="www.google.com"):
    """
    Add a New Job to a Schedule

    """
    schedule_ssl_check = Schedule.add_job(check_host_certificate, 'interval', seconds=time_in_seconds,id=host,args=[host])
    return {"scheduled":True,"job_id":schedule_ssl_check.id}

@app.delete("/schedule/host_ssl_check/",response_model=JobCreateDeleteResponse,tags=["schedule"])
async def remove_ssl_check_from_scheduler(host="www.google.com"):
    """
    Remove a Job from a Schedule

    """
    Schedule.remove_job(host)
    return {"scheduled":False,"job_id":host}

