from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from sqlalchemy import create_engine, Column, Integer, String, Boolean, JSON, DateTime, Text, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime, date
import json
import uuid
import os

# ============ DATABASE ============
SQLALCHEMY_DATABASE_URL = "sqlite:///./privy.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ============ MODELS ============

class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    owner = Column(String(255))
    department = Column(String(100))
    vendor = Column(String(255))
    development_stage = Column(String(50))
    go_live_date = Column(DateTime)
    status = Column(String(50), default="draft")
    created_by = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    data_mappings = relationship("DataMapping", back_populates="project")
    ropas = relationship("RoPA", back_populates="project")
    dpias = relationship("DPIA", back_populates="project")
    vendors = relationship("VendorAssessment", back_populates="project")
    evidence = relationship("Evidence", back_populates="project")
    dsars = relationship("DSAR", back_populates="project")

class DataMapping(Base):
    __tablename__ = "data_mappings"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    personal_data_category = Column(String(100))
    sensitive_data_category = Column(String(100))
    data_subject_category = Column(String(100))
    source_of_data = Column(String(255))
    storage_location = Column(String(255))
    recipients = Column(JSON, default=[])
    third_parties = Column(JSON, default=[])
    cross_border_transfers = Column(JSON, default=[])
    data_flow_diagram = Column(String(500))
    visual_data_map = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    project = relationship("Project", back_populates="data_mappings")

class RoPA(Base):
    __tablename__ = "ropa"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    processing_activity = Column(String(255))
    purpose = Column(Text)
    lawful_basis = Column(String(100))
    data_subjects = Column(JSON, default=[])
    personal_data_categories = Column(JSON, default=[])
    recipients = Column(JSON, default=[])
    retention_period = Column(String(100))
    security_measures = Column(JSON, default=[])
    international_transfers = Column(JSON, default=[])
    controller_name = Column(String(255))
    controller_email = Column(String(255))
    processor_name = Column(String(255))
    processor_email = Column(String(255))
    data_protection_officer = Column(String(255))
    dpo_email = Column(String(255))
    registration_number = Column(String(100))
    status = Column(String(50), default="draft")
    approved_by = Column(String(255))
    approved_at = Column(DateTime)
    version = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    project = relationship("Project", back_populates="ropas")

class DPIA(Base):
    __tablename__ = "dpia"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    ropa_id = Column(Integer, ForeignKey("ropa.id"), nullable=True)
    
    # Step 1: Screening
    processes_sensitive_data = Column(Boolean, default=False)
    uses_ai = Column(Boolean, default=False)
    monitors_individuals = Column(Boolean, default=False)
    processes_children_data = Column(Boolean, default=False)
    automated_decision_making = Column(Boolean, default=False)
    large_scale_processing = Column(Boolean, default=False)
    systematic_monitoring = Column(Boolean, default=False)
    innovative_technology = Column(Boolean, default=False)
    dpia_required = Column(Boolean, default=False)
    screening_notes = Column(Text)
    
    # Step 2: Description of Processing
    name = Column(String(255))
    owner_department = Column(String(100))
    contact_email = Column(String(255))
    processing_type = Column(String(50))
    classification = Column(String(50))
    data_subjects_count = Column(Integer)
    lawful_basis = Column(String(100))
    purpose = Column(Text)
    data_types = Column(JSON, default=[])
    high_risk_type = Column(String(100))
    data_flow = Column(Text)
    
    # Step 3: Necessity & Proportionality
    lawful_basis_description = Column(Text)
    achieves_purpose = Column(String(20))
    data_quality_minimization = Column(Text)
    consent_obtained = Column(Text)
    alternative_approaches = Column(Text)
    information_to_individuals = Column(Text)
    parties_involved = Column(Text)
    international_transfers = Column(Text)
    compliance_measures = Column(Text)
    safeguarding_measures = Column(Text)
    
    # Step 4: Risk Identification
    risks = Column(JSON, default=[])
    
    # Step 5: Privacy Risk Evaluation
    # 5.1 Impact Assessment
    impact_financial = Column(Boolean, default=False)
    impact_identity = Column(Boolean, default=False)
    impact_discrimination = Column(Boolean, default=False)
    impact_reputation = Column(Boolean, default=False)
    impact_confidentiality = Column(Boolean, default=False)
    impact_physical = Column(Boolean, default=False)
    impact_psychological = Column(Boolean, default=False)
    impact_rights = Column(Boolean, default=False)
    impact_other = Column(Boolean, default=False)
    impact_rating = Column(String(20), default="Medium")
    impact_description = Column(Text)
    
    # 5.2 Likelihood Assessment
    likelihood_sensitive = Column(Boolean, default=False)
    likelihood_large_volume = Column(Boolean, default=False)
    likelihood_automated = Column(Boolean, default=False)
    likelihood_third_party = Column(Boolean, default=False)
    likelihood_international = Column(Boolean, default=False)
    likelihood_children = Column(Boolean, default=False)
    likelihood_new_tech = Column(Boolean, default=False)
    
    # 5.3 Existing Controls
    control_encryption = Column(Boolean, default=False)
    control_access = Column(Boolean, default=False)
    control_mfa = Column(Boolean, default=False)
    control_logging = Column(Boolean, default=False)
    control_minimization = Column(Boolean, default=False)
    control_retention = Column(Boolean, default=False)
    control_vendor = Column(Boolean, default=False)
    control_training = Column(Boolean, default=False)
    control_incident = Column(Boolean, default=False)
    control_other = Column(Boolean, default=False)
    control_description = Column(Text)
    
    # 5.5 Mitigation Plan
    mitigation_action = Column(Text)
    mitigation_owner = Column(String(255))
    mitigation_due_date = Column(DateTime)
    mitigation_status = Column(String(20), default="Open")
    mitigation_notes = Column(Text)
    
    # Step 6: Privacy-by-Design
    pbd_minimization = Column(Boolean, default=False)
    pbd_retention = Column(Boolean, default=False)
    pbd_encryption = Column(Boolean, default=False)
    pbd_mfa = Column(Boolean, default=False)
    pbd_access = Column(Boolean, default=False)
    pbd_audit = Column(Boolean, default=False)
    pbd_consent = Column(Boolean, default=False)
    pbd_anonymization = Column(Boolean, default=False)
    pbd_breach = Column(Boolean, default=False)
    pbd_training = Column(Boolean, default=False)
    pbd_notes = Column(Text)
    
    # Status & workflow
    status = Column(String(50), default="draft")
    approved_by = Column(String(255))
    approved_at = Column(DateTime)
    version = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    project = relationship("Project", back_populates="dpias")

class VendorAssessment(Base):
    __tablename__ = "vendor_assessments"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    vendor_name = Column(String(255))
    hosting_location = Column(String(100))
    security_certifications = Column(JSON, default=[])
    dpa_signed = Column(Boolean, default=False)
    dpa_date = Column(DateTime)
    sub_processors = Column(JSON, default=[])
    risk_rating = Column(String(50))
    assessment_notes = Column(Text)
    assessment_date = Column(DateTime)
    next_assessment_date = Column(DateTime)
    status = Column(String(50), default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    project = relationship("Project", back_populates="vendors")

class ApplicationInventory(Base):
    __tablename__ = "application_inventory"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    application_name = Column(String(255))
    application_owner = Column(String(255))
    department = Column(String(100))
    description = Column(Text)
    data_classification = Column(String(50))
    hosting_environment = Column(String(50))
    cloud_provider = Column(String(100))
    data_processed = Column(JSON, default=[])
    users = Column(Integer)
    third_party_integrations = Column(JSON, default=[])
    security_controls = Column(JSON, default=[])
    compliance_status = Column(String(50), default="not_assessed")
    last_assessment_date = Column(DateTime)
    next_assessment_date = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ThirdPartyInventory(Base):
    __tablename__ = "third_party_inventory"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    third_party_name = Column(String(255))
    service_type = Column(String(100))
    contact_person = Column(String(255))
    contact_email = Column(String(255))
    contact_phone = Column(String(50))
    jurisdiction = Column(String(100))
    applicable_law = Column(String(100))
    processing_role = Column(String(50))
    data_shared = Column(JSON, default=[])
    dpa_signed = Column(Boolean, default=False)
    dpa_date = Column(DateTime)
    security_certifications = Column(JSON, default=[])
    risk_rating = Column(String(50))
    status = Column(String(50), default="active")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SecurityControl(Base):
    __tablename__ = "security_controls"
    id = Column(Integer, primary_key=True, index=True)
    control_name = Column(String(255))
    control_description = Column(Text)
    control_type = Column(String(50))
    iso_27001_mapping = Column(JSON, default=[])
    nist_mapping = Column(JSON, default=[])
    kenya_dpa_mapping = Column(JSON, default=[])
    gdpr_mapping = Column(JSON, default=[])
    implementation_status = Column(String(50), default="not_implemented")
    evidence_url = Column(String(500))
    owner = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    title = Column(String(255))
    description = Column(Text)
    document_type = Column(String(50))
    file_url = Column(String(500))
    uploaded_by = Column(String(255))
    upload_date = Column(DateTime, default=datetime.utcnow)
    version = Column(String(20), default="1.0")
    project = relationship("Project", back_populates="evidence")

class DSAR(Base):
    __tablename__ = "dsar"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True)
    full_name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    phone = Column(String(50))
    message = Column(Text, nullable=False)
    request_type = Column(String(50))
    status = Column(String(50), default="draft")
    consent_given = Column(Boolean, default=False)
    response = Column(Text)
    responded_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    project = relationship("Project", back_populates="dsars")

Base.metadata.create_all(bind=engine)

# ============ PYDANTIC SCHEMAS ============

class ProjectCreate(BaseModel):
    name: str
    owner: Optional[str] = ""
    department: Optional[str] = ""
    vendor: Optional[str] = ""
    development_stage: Optional[str] = "Requirements"
    go_live_date: Optional[datetime] = None
    created_by: Optional[str] = ""

class ProjectResponse(BaseModel):
    id: int
    name: str
    owner: Optional[str]
    department: Optional[str]
    vendor: Optional[str]
    development_stage: Optional[str]
    go_live_date: Optional[datetime]
    status: str
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

class DataMappingCreate(BaseModel):
    project_id: int
    personal_data_category: Optional[str] = ""
    sensitive_data_category: Optional[str] = ""
    data_subject_category: Optional[str] = ""
    source_of_data: Optional[str] = ""
    storage_location: Optional[str] = ""
    recipients: List[str] = []
    third_parties: List[str] = []
    cross_border_transfers: List[Dict] = []
    data_flow_diagram: Optional[str] = ""
    visual_data_map: Optional[str] = ""

class DataMappingResponse(BaseModel):
    id: int
    project_id: int
    personal_data_category: Optional[str]
    sensitive_data_category: Optional[str]
    data_subject_category: Optional[str]
    source_of_data: Optional[str]
    storage_location: Optional[str]
    recipients: List[str]
    third_parties: List[str]
    cross_border_transfers: List[Dict]
    data_flow_diagram: Optional[str]
    visual_data_map: Optional[str]
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

class RoPACreate(BaseModel):
    project_id: int
    processing_activity: str
    purpose: str
    lawful_basis: str
    data_subjects: List[str] = []
    personal_data_categories: List[str] = []
    recipients: List[str] = []
    retention_period: str = ""
    security_measures: List[str] = []
    international_transfers: List[Dict] = []
    controller_name: Optional[str] = ""
    controller_email: Optional[str] = ""
    processor_name: Optional[str] = ""
    processor_email: Optional[str] = ""
    data_protection_officer: Optional[str] = ""
    dpo_email: Optional[str] = ""
    registration_number: Optional[str] = ""

class RoPAResponse(BaseModel):
    id: int
    project_id: int
    processing_activity: str
    purpose: str
    lawful_basis: str
    data_subjects: List[str]
    personal_data_categories: List[str]
    recipients: List[str]
    retention_period: str
    security_measures: List[str]
    international_transfers: List[Dict]
    controller_name: Optional[str]
    controller_email: Optional[str]
    processor_name: Optional[str]
    processor_email: Optional[str]
    data_protection_officer: Optional[str]
    dpo_email: Optional[str]
    registration_number: Optional[str]
    status: str
    approved_by: Optional[str]
    approved_at: Optional[datetime]
    version: int
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

class DPIACreate(BaseModel):
    project_id: int
    ropa_id: Optional[int] = None
    processes_sensitive_data: bool = False
    uses_ai: bool = False
    monitors_individuals: bool = False
    processes_children_data: bool = False
    automated_decision_making: bool = False
    large_scale_processing: bool = False
    systematic_monitoring: bool = False
    innovative_technology: bool = False
    screening_notes: str = ""
    name: str = ""
    owner_department: str = ""
    contact_email: str = ""
    processing_type: str = "Controller"
    classification: str = "Personal"
    data_subjects_count: int = 0
    lawful_basis: str = ""
    purpose: str = ""
    data_types: List[str] = []
    high_risk_type: str = ""
    data_flow: str = ""
    lawful_basis_description: str = ""
    achieves_purpose: str = "true"
    data_quality_minimization: str = ""
    consent_obtained: str = ""
    alternative_approaches: str = ""
    information_to_individuals: str = ""
    parties_involved: str = ""
    international_transfers: str = ""
    compliance_measures: str = ""
    safeguarding_measures: str = ""
    risks: List[Dict] = []
    impact_financial: bool = False
    impact_identity: bool = False
    impact_discrimination: bool = False
    impact_reputation: bool = False
    impact_confidentiality: bool = False
    impact_physical: bool = False
    impact_psychological: bool = False
    impact_rights: bool = False
    impact_other: bool = False
    impact_rating: str = "Medium"
    impact_description: str = ""
    likelihood_sensitive: bool = False
    likelihood_large_volume: bool = False
    likelihood_automated: bool = False
    likelihood_third_party: bool = False
    likelihood_international: bool = False
    likelihood_children: bool = False
    likelihood_new_tech: bool = False
    control_encryption: bool = False
    control_access: bool = False
    control_mfa: bool = False
    control_logging: bool = False
    control_minimization: bool = False
    control_retention: bool = False
    control_vendor: bool = False
    control_training: bool = False
    control_incident: bool = False
    control_other: bool = False
    control_description: str = ""
    mitigation_action: str = ""
    mitigation_owner: str = ""
    mitigation_due_date: Optional[datetime] = None
    mitigation_status: str = "Open"
    mitigation_notes: str = ""
    pbd_minimization: bool = False
    pbd_retention: bool = False
    pbd_encryption: bool = False
    pbd_mfa: bool = False
    pbd_access: bool = False
    pbd_audit: bool = False
    pbd_consent: bool = False
    pbd_anonymization: bool = False
    pbd_breach: bool = False
    pbd_training: bool = False
    pbd_notes: str = ""

class DPIAResponse(BaseModel):
    id: int
    project_id: int
    ropa_id: Optional[int]
    processes_sensitive_data: bool
    uses_ai: bool
    monitors_individuals: bool
    processes_children_data: bool
    automated_decision_making: bool
    large_scale_processing: bool
    systematic_monitoring: bool
    innovative_technology: bool
    dpia_required: bool
    screening_notes: str
    name: str
    owner_department: str
    contact_email: str
    processing_type: str
    classification: str
    data_subjects_count: int
    lawful_basis: str
    purpose: str
    data_types: List[str]
    high_risk_type: str
    data_flow: str
    lawful_basis_description: str
    achieves_purpose: str
    data_quality_minimization: str
    consent_obtained: str
    alternative_approaches: str
    information_to_individuals: str
    parties_involved: str
    international_transfers: str
    compliance_measures: str
    safeguarding_measures: str
    risks: List[Dict]
    impact_financial: bool
    impact_identity: bool
    impact_discrimination: bool
    impact_reputation: bool
    impact_confidentiality: bool
    impact_physical: bool
    impact_psychological: bool
    impact_rights: bool
    impact_other: bool
    impact_rating: str
    impact_description: str
    likelihood_sensitive: bool
    likelihood_large_volume: bool
    likelihood_automated: bool
    likelihood_third_party: bool
    likelihood_international: bool
    likelihood_children: bool
    likelihood_new_tech: bool
    control_encryption: bool
    control_access: bool
    control_mfa: bool
    control_logging: bool
    control_minimization: bool
    control_retention: bool
    control_vendor: bool
    control_training: bool
    control_incident: bool
    control_other: bool
    control_description: str
    mitigation_action: str
    mitigation_owner: str
    mitigation_due_date: Optional[datetime]
    mitigation_status: str
    mitigation_notes: str
    pbd_minimization: bool
    pbd_retention: bool
    pbd_encryption: bool
    pbd_mfa: bool
    pbd_access: bool
    pbd_audit: bool
    pbd_consent: bool
    pbd_anonymization: bool
    pbd_breach: bool
    pbd_training: bool
    pbd_notes: str
    status: str
    approved_by: Optional[str]
    approved_at: Optional[datetime]
    version: int
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

class VendorAssessmentCreate(BaseModel):
    project_id: int
    vendor_name: str
    hosting_location: str = ""
    security_certifications: List[str] = []
    dpa_signed: bool = False
    dpa_date: Optional[datetime] = None
    sub_processors: List[str] = []
    risk_rating: str = "Medium"
    assessment_notes: str = ""
    assessment_date: Optional[datetime] = None
    next_assessment_date: Optional[datetime] = None

class VendorAssessmentResponse(BaseModel):
    id: int
    project_id: int
    vendor_name: str
    hosting_location: str
    security_certifications: List[str]
    dpa_signed: bool
    dpa_date: Optional[datetime]
    sub_processors: List[str]
    risk_rating: str
    assessment_notes: str
    assessment_date: Optional[datetime]
    next_assessment_date: Optional[datetime]
    status: str
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

class ApplicationInventoryCreate(BaseModel):
    project_id: int
    application_name: str
    application_owner: str = ""
    department: str = ""
    description: str = ""
    data_classification: str = "Personal"
    hosting_environment: str = "Cloud"
    cloud_provider: str = ""
    data_processed: List[str] = []
    users: int = 0
    third_party_integrations: List[str] = []
    security_controls: List[str] = []
    last_assessment_date: Optional[datetime] = None
    next_assessment_date: Optional[datetime] = None

class ApplicationInventoryResponse(BaseModel):
    id: int
    project_id: int
    application_name: str
    application_owner: str
    department: str
    description: str
    data_classification: str
    hosting_environment: str
    cloud_provider: str
    data_processed: List[str]
    users: int
    third_party_integrations: List[str]
    security_controls: List[str]
    compliance_status: str
    last_assessment_date: Optional[datetime]
    next_assessment_date: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

class ThirdPartyInventoryCreate(BaseModel):
    project_id: int
    third_party_name: str
    service_type: str = ""
    contact_person: str = ""
    contact_email: str = ""
    contact_phone: str = ""
    jurisdiction: str = "Kenya"
    applicable_law: str = "Kenya Data Protection Act 2019"
    processing_role: str = "Processor"
    data_shared: List[str] = []
    dpa_signed: bool = False
    dpa_date: Optional[datetime] = None
    security_certifications: List[str] = []
    risk_rating: str = "Medium"

class ThirdPartyInventoryResponse(BaseModel):
    id: int
    project_id: int
    third_party_name: str
    service_type: str
    contact_person: str
    contact_email: str
    contact_phone: str
    jurisdiction: str
    applicable_law: str
    processing_role: str
    data_shared: List[str]
    dpa_signed: bool
    dpa_date: Optional[datetime]
    security_certifications: List[str]
    risk_rating: str
    status: str
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

class SecurityControlCreate(BaseModel):
    control_name: str
    control_description: str
    control_type: str = "Technical"
    iso_27001_mapping: List[str] = []
    nist_mapping: List[str] = []
    kenya_dpa_mapping: List[str] = []
    gdpr_mapping: List[str] = []
    implementation_status: str = "not_implemented"
    evidence_url: str = ""
    owner: str = ""

class SecurityControlResponse(BaseModel):
    id: int
    control_name: str
    control_description: str
    control_type: str
    iso_27001_mapping: List[str]
    nist_mapping: List[str]
    kenya_dpa_mapping: List[str]
    gdpr_mapping: List[str]
    implementation_status: str
    evidence_url: str
    owner: str
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

class EvidenceCreate(BaseModel):
    project_id: int
    title: str
    description: str = ""
    document_type: str
    file_url: str
    uploaded_by: str = ""
    version: str = "1.0"

class EvidenceResponse(BaseModel):
    id: int
    project_id: int
    title: str
    description: str
    document_type: str
    file_url: str
    uploaded_by: str
    upload_date: datetime
    version: str
    class Config:
        from_attributes = True

class DSARCreate(BaseModel):
    project_id: Optional[int] = None
    full_name: str
    email: str
    phone: str = ""
    message: str
    request_type: str
    consent_given: bool = False

class DSARResponse(BaseModel):
    id: int
    project_id: Optional[int]
    full_name: str
    email: str
    phone: str
    message: str
    request_type: str
    status: str
    consent_given: bool
    response: Optional[str]
    responded_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

class DSARUpdate(BaseModel):
    status: str
    response: Optional[str] = ""

# ============ FASTAPI APP ============
app = FastAPI(title="Privy - Compliance Management Platform")
# ============ SERVE FRONTEND FILES ============

@app.get("/")
async def root():
    """Serve the login page as the root URL"""
    with open("auth.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.get("/{filename}")
async def serve_static(filename: str):
    """Serve any HTML or static file"""
    if filename.endswith('.html'):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                return HTMLResponse(content=f.read())
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Page not found")
    else:
        try:
            return FileResponse(filename)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="File not found")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# ============ PROJECT ENDPOINTS ============
@app.post("/api/projects", response_model=ProjectResponse)
def create_project(project: ProjectCreate, db: Session = Depends(get_db)):
    db_project = Project(**project.dict())
    db.add(db_project)
    db.commit()
    db.refresh(db_project)
    return db_project

@app.get("/api/projects", response_model=List[ProjectResponse])
def list_projects(db: Session = Depends(get_db)):
    return db.query(Project).all()

@app.get("/api/projects/{project_id}", response_model=ProjectResponse)
def get_project(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@app.put("/api/projects/{project_id}", response_model=ProjectResponse)
def update_project(project_id: int, project: ProjectCreate, db: Session = Depends(get_db)):
    db_project = db.query(Project).filter(Project.id == project_id).first()
    if not db_project:
        raise HTTPException(status_code=404, detail="Project not found")
    for key, value in project.dict().items():
        setattr(db_project, key, value)
    db_project.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_project)
    return db_project

@app.put("/api/projects/{project_id}/status")
def update_project_status(project_id: int, status: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project.status = status
    project.updated_at = datetime.utcnow()
    db.commit()
    return {"message": f"Project status updated to {status}"}

# ============ DATA MAPPING ENDPOINTS ============
@app.post("/api/data-mapping", response_model=DataMappingResponse)
def create_data_mapping(mapping: DataMappingCreate, db: Session = Depends(get_db)):
    db_mapping = DataMapping(**mapping.dict())
    db.add(db_mapping)
    db.commit()
    db.refresh(db_mapping)
    return db_mapping

@app.get("/api/data-mapping/{project_id}", response_model=List[DataMappingResponse])
def list_data_mappings(project_id: int, db: Session = Depends(get_db)):
    return db.query(DataMapping).filter(DataMapping.project_id == project_id).all()

@app.put("/api/data-mapping/{mapping_id}", response_model=DataMappingResponse)
def update_data_mapping(mapping_id: int, mapping: DataMappingCreate, db: Session = Depends(get_db)):
    db_mapping = db.query(DataMapping).filter(DataMapping.id == mapping_id).first()
    if not db_mapping:
        raise HTTPException(status_code=404, detail="Data mapping not found")
    for key, value in mapping.dict().items():
        setattr(db_mapping, key, value)
    db_mapping.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_mapping)
    return db_mapping

# ============ ROPA ENDPOINTS ============
@app.post("/api/ropa", response_model=RoPAResponse)
def create_ropa(ropa: RoPACreate, db: Session = Depends(get_db)):
    db_ropa = RoPA(**ropa.dict())
    db.add(db_ropa)
    db.commit()
    db.refresh(db_ropa)
    return db_ropa

@app.get("/api/ropa", response_model=List[RoPAResponse])
def list_ropa(db: Session = Depends(get_db)):
    return db.query(RoPA).all()

@app.get("/api/ropa/{project_id}", response_model=List[RoPAResponse])
def get_ropa_by_project(project_id: int, db: Session = Depends(get_db)):
    return db.query(RoPA).filter(RoPA.project_id == project_id).all()

@app.get("/api/ropa/single/{ropa_id}", response_model=RoPAResponse)
def get_ropa(ropa_id: int, db: Session = Depends(get_db)):
    ropa = db.query(RoPA).filter(RoPA.id == ropa_id).first()
    if not ropa:
        raise HTTPException(status_code=404, detail="RoPA not found")
    return ropa

@app.put("/api/ropa/{ropa_id}", response_model=RoPAResponse)
def update_ropa(ropa_id: int, ropa: RoPACreate, db: Session = Depends(get_db)):
    db_ropa = db.query(RoPA).filter(RoPA.id == ropa_id).first()
    if not db_ropa:
        raise HTTPException(status_code=404, detail="RoPA not found")
    for key, value in ropa.dict().items():
        setattr(db_ropa, key, value)
    db_ropa.updated_at = datetime.utcnow()
    db_ropa.version += 1
    db.commit()
    db.refresh(db_ropa)
    return db_ropa

@app.put("/api/ropa/{ropa_id}/status")
def update_ropa_status(ropa_id: int, status: str, approved_by: str = "", db: Session = Depends(get_db)):
    ropa = db.query(RoPA).filter(RoPA.id == ropa_id).first()
    if not ropa:
        raise HTTPException(status_code=404, detail="RoPA not found")
    ropa.status = status
    if status == "approved":
        ropa.approved_by = approved_by
        ropa.approved_at = datetime.utcnow()
    ropa.updated_at = datetime.utcnow()
    db.commit()
    return {"message": f"RoPA status updated to {status}"}

# ============ DPIA ENDPOINTS ============
@app.post("/api/dpia", response_model=DPIAResponse)
def create_dpia(dpia: DPIACreate, db: Session = Depends(get_db)):
    dpia_required = (
        dpia.processes_sensitive_data or
        dpia.uses_ai or
        dpia.monitors_individuals or
        dpia.processes_children_data or
        dpia.automated_decision_making or
        dpia.large_scale_processing or
        dpia.systematic_monitoring or
        dpia.innovative_technology
    )
    
    db_dpia = DPIA(**dpia.dict())
    db_dpia.dpia_required = dpia_required
    db.add(db_dpia)
    db.commit()
    db.refresh(db_dpia)
    
    if dpia.ropa_id:
        ropa = db.query(RoPA).filter(RoPA.id == dpia.ropa_id).first()
        if ropa:
            ropa.dpia_status = "in_progress"
            db.commit()
    
    return db_dpia

@app.get("/api/dpia", response_model=List[DPIAResponse])
def list_dpia(db: Session = Depends(get_db)):
    return db.query(DPIA).all()

@app.get("/api/dpia/{project_id}", response_model=List[DPIAResponse])
def get_dpia_by_project(project_id: int, db: Session = Depends(get_db)):
    return db.query(DPIA).filter(DPIA.project_id == project_id).all()

@app.get("/api/dpia/single/{dpia_id}", response_model=DPIAResponse)
def get_dpia(dpia_id: int, db: Session = Depends(get_db)):
    dpia = db.query(DPIA).filter(DPIA.id == dpia_id).first()
    if not dpia:
        raise HTTPException(status_code=404, detail="DPIA not found")
    return dpia

@app.put("/api/dpia/{dpia_id}", response_model=DPIAResponse)
def update_dpia(dpia_id: int, dpia: DPIACreate, db: Session = Depends(get_db)):
    db_dpia = db.query(DPIA).filter(DPIA.id == dpia_id).first()
    if not db_dpia:
        raise HTTPException(status_code=404, detail="DPIA not found")
    
    dpia_required = (
        dpia.processes_sensitive_data or
        dpia.uses_ai or
        dpia.monitors_individuals or
        dpia.processes_children_data or
        dpia.automated_decision_making or
        dpia.large_scale_processing or
        dpia.systematic_monitoring or
        dpia.innovative_technology
    )
    
    for key, value in dpia.dict().items():
        setattr(db_dpia, key, value)
    db_dpia.dpia_required = dpia_required
    db_dpia.updated_at = datetime.utcnow()
    db_dpia.version += 1
    db.commit()
    db.refresh(db_dpia)
    return db_dpia

@app.put("/api/dpia/{dpia_id}/status")
def update_dpia_status(dpia_id: int, status: str, approved_by: str = "", db: Session = Depends(get_db)):
    dpia = db.query(DPIA).filter(DPIA.id == dpia_id).first()
    if not dpia:
        raise HTTPException(status_code=404, detail="DPIA not found")
    dpia.status = status
    if status == "approved":
        dpia.approved_by = approved_by
        dpia.approved_at = datetime.utcnow()
    dpia.updated_at = datetime.utcnow()
    db.commit()
    return {"message": f"DPIA status updated to {status}"}

# ============ VENDOR ASSESSMENT ENDPOINTS ============
@app.post("/api/vendors", response_model=VendorAssessmentResponse)
def create_vendor(vendor: VendorAssessmentCreate, db: Session = Depends(get_db)):
    db_vendor = VendorAssessment(**vendor.dict())
    db.add(db_vendor)
    db.commit()
    db.refresh(db_vendor)
    return db_vendor

@app.get("/api/vendors/{project_id}", response_model=List[VendorAssessmentResponse])
def list_vendors(project_id: int, db: Session = Depends(get_db)):
    return db.query(VendorAssessment).filter(VendorAssessment.project_id == project_id).all()

@app.put("/api/vendors/{vendor_id}", response_model=VendorAssessmentResponse)
def update_vendor(vendor_id: int, vendor: VendorAssessmentCreate, db: Session = Depends(get_db)):
    db_vendor = db.query(VendorAssessment).filter(VendorAssessment.id == vendor_id).first()
    if not db_vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    for key, value in vendor.dict().items():
        setattr(db_vendor, key, value)
    db_vendor.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_vendor)
    return db_vendor

# ============ APPLICATION INVENTORY ENDPOINTS ============
@app.post("/api/applications", response_model=ApplicationInventoryResponse)
def create_application(app: ApplicationInventoryCreate, db: Session = Depends(get_db)):
    db_app = ApplicationInventory(**app.dict())
    db.add(db_app)
    db.commit()
    db.refresh(db_app)
    return db_app

@app.get("/api/applications/{project_id}", response_model=List[ApplicationInventoryResponse])
def list_applications(project_id: int, db: Session = Depends(get_db)):
    return db.query(ApplicationInventory).filter(ApplicationInventory.project_id == project_id).all()

@app.put("/api/applications/{app_id}", response_model=ApplicationInventoryResponse)
def update_application(app_id: int, app: ApplicationInventoryCreate, db: Session = Depends(get_db)):
    db_app = db.query(ApplicationInventory).filter(ApplicationInventory.id == app_id).first()
    if not db_app:
        raise HTTPException(status_code=404, detail="Application not found")
    for key, value in app.dict().items():
        setattr(db_app, key, value)
    db_app.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_app)
    return db_app

# ============ THIRD PARTY INVENTORY ENDPOINTS ============
@app.post("/api/third-parties", response_model=ThirdPartyInventoryResponse)
def create_third_party(tp: ThirdPartyInventoryCreate, db: Session = Depends(get_db)):
    db_tp = ThirdPartyInventory(**tp.dict())
    db.add(db_tp)
    db.commit()
    db.refresh(db_tp)
    return db_tp

@app.get("/api/third-parties/{project_id}", response_model=List[ThirdPartyInventoryResponse])
def list_third_parties(project_id: int, db: Session = Depends(get_db)):
    return db.query(ThirdPartyInventory).filter(ThirdPartyInventory.project_id == project_id).all()

@app.put("/api/third-parties/{tp_id}", response_model=ThirdPartyInventoryResponse)
def update_third_party(tp_id: int, tp: ThirdPartyInventoryCreate, db: Session = Depends(get_db)):
    db_tp = db.query(ThirdPartyInventory).filter(ThirdPartyInventory.id == tp_id).first()
    if not db_tp:
        raise HTTPException(status_code=404, detail="Third party not found")
    for key, value in tp.dict().items():
        setattr(db_tp, key, value)
    db_tp.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_tp)
    return db_tp

# ============ SECURITY CONTROLS ENDPOINTS ============
@app.post("/api/controls", response_model=SecurityControlResponse)
def create_control(control: SecurityControlCreate, db: Session = Depends(get_db)):
    db_control = SecurityControl(**control.dict())
    db.add(db_control)
    db.commit()
    db.refresh(db_control)
    return db_control

@app.get("/api/controls", response_model=List[SecurityControlResponse])
def list_controls(db: Session = Depends(get_db)):
    return db.query(SecurityControl).all()

@app.put("/api/controls/{control_id}", response_model=SecurityControlResponse)
def update_control(control_id: int, control: SecurityControlCreate, db: Session = Depends(get_db)):
    db_control = db.query(SecurityControl).filter(SecurityControl.id == control_id).first()
    if not db_control:
        raise HTTPException(status_code=404, detail="Control not found")
    for key, value in control.dict().items():
        setattr(db_control, key, value)
    db_control.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_control)
    return db_control

# ============ EVIDENCE ENDPOINTS ============
@app.post("/api/evidence", response_model=EvidenceResponse)
def create_evidence(evidence: EvidenceCreate, db: Session = Depends(get_db)):
    db_evidence = Evidence(**evidence.dict())
    db.add(db_evidence)
    db.commit()
    db.refresh(db_evidence)
    return db_evidence

@app.get("/api/evidence/{project_id}", response_model=List[EvidenceResponse])
def list_evidence(project_id: int, db: Session = Depends(get_db)):
    return db.query(Evidence).filter(Evidence.project_id == project_id).all()

@app.put("/api/evidence/{evidence_id}", response_model=EvidenceResponse)
def update_evidence(evidence_id: int, evidence: EvidenceCreate, db: Session = Depends(get_db)):
    db_evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not db_evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    for key, value in evidence.dict().items():
        setattr(db_evidence, key, value)
    db_evidence.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_evidence)
    return db_evidence

# ============ DSAR ENDPOINTS ============
@app.post("/api/dsar", response_model=DSARResponse)
def create_dsar(dsar: DSARCreate, db: Session = Depends(get_db)):
    db_dsar = DSAR(**dsar.dict())
    db.add(db_dsar)
    db.commit()
    db.refresh(db_dsar)
    return db_dsar

@app.get("/api/dsar", response_model=List[DSARResponse])
def list_dsar(db: Session = Depends(get_db)):
    return db.query(DSAR).all()

@app.get("/api/dsar/{dsar_id}", response_model=DSARResponse)
def get_dsar(dsar_id: int, db: Session = Depends(get_db)):
    dsar = db.query(DSAR).filter(DSAR.id == dsar_id).first()
    if not dsar:
        raise HTTPException(status_code=404, detail="DSAR not found")
    return dsar

@app.put("/api/dsar/{dsar_id}", response_model=DSARResponse)
def update_dsar(dsar_id: int, dsar_update: DSARUpdate, db: Session = Depends(get_db)):
    dsar = db.query(DSAR).filter(DSAR.id == dsar_id).first()
    if not dsar:
        raise HTTPException(status_code=404, detail="DSAR not found")
    
    dsar.status = dsar_update.status
    if dsar_update.response:
        dsar.response = dsar_update.response
    if dsar_update.status in ["completed", "rejected"]:
        dsar.responded_at = datetime.utcnow()
    dsar.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(dsar)
    return dsar

@app.delete("/api/dsar/{dsar_id}")
def delete_dsar(dsar_id: int, db: Session = Depends(get_db)):
    dsar = db.query(DSAR).filter(DSAR.id == dsar_id).first()
    if not dsar:
        raise HTTPException(status_code=404, detail="DSAR not found")
    db.delete(dsar)
    db.commit()
    return {"message": "DSAR deleted successfully"}

# ============ DSAR PORTAL (Public Form) ============
@app.get("/api/dsar-portal")
def dsar_portal():
    """Public DSAR submission portal - HTML page for data subjects"""
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Data Subject Access Request - Privy</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #f1f5f9;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .container {
                max-width: 600px;
                width: 100%;
                background: #fff;
                border-radius: 16px;
                padding: 40px;
                box-shadow: 0 4px 24px rgba(0,0,0,0.1);
            }
            .header {
                text-align: center;
                margin-bottom: 30px;
            }
            .header .logo { font-size: 48px; }
            .header h1 {
                font-size: 24px;
                color: #0f172a;
                margin-top: 8px;
            }
            .header p {
                color: #64748b;
                font-size: 14px;
                margin-top: 4px;
            }
            .form-group {
                margin-bottom: 16px;
            }
            .form-group label {
                display: block;
                font-weight: 600;
                font-size: 14px;
                margin-bottom: 4px;
                color: #334155;
            }
            .form-group label .required { color: #f56565; }
            .form-control {
                width: 100%;
                padding: 10px 14px;
                border: 2px solid #e2e8f0;
                border-radius: 8px;
                font-size: 14px;
                font-family: inherit;
                transition: border-color 0.2s;
                background: #fff;
            }
            .form-control:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102,126,234,0.15);
            }
            select.form-control {
                appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23475569' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: right 12px center;
                padding-right: 36px;
            }
            textarea.form-control {
                resize: vertical;
                min-height: 100px;
            }
            .btn {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 12px 30px;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
                font-family: inherit;
                background: #667eea;
                color: #fff;
                width: 100%;
                justify-content: center;
            }
            .btn:hover {
                background: #5a67d8;
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(102,126,234,0.3);
            }
            .checkbox-group {
                display: flex;
                align-items: flex-start;
                gap: 10px;
                padding: 8px 0;
            }
            .checkbox-group input[type="checkbox"] {
                width: 18px;
                height: 18px;
                margin-top: 2px;
                accent-color: #667eea;
                flex-shrink: 0;
                cursor: pointer;
            }
            .checkbox-group label {
                font-size: 14px;
                color: #475569;
                cursor: pointer;
            }
            .alert {
                padding: 12px 16px;
                border-radius: 8px;
                margin-bottom: 16px;
                display: none;
            }
            .alert.success {
                display: block;
                background: #c6f6d5;
                color: #22543d;
                border: 1px solid #9ae6b4;
            }
            .alert.error {
                display: block;
                background: #fed7d7;
                color: #9b2c2c;
                border: 1px solid #feb2b2;
            }
            .footer {
                text-align: center;
                margin-top: 24px;
                padding-top: 16px;
                border-top: 1px solid #e2e8f0;
                color: #94a3b8;
                font-size: 13px;
            }
            .privacy-notice {
                background: #f8fafc;
                padding: 12px 16px;
                border-radius: 8px;
                font-size: 13px;
                color: #64748b;
                margin-bottom: 16px;
                border-left: 3px solid #667eea;
            }
            .privacy-notice strong { color: #334155; }
            @media (max-width: 500px) {
                .container { padding: 24px; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🔒</div>
                <h1>Data Subject Access Request</h1>
                <p>Submit a request to access, correct, or delete your personal data</p>
            </div>

            <div id="alert" class="alert"></div>

            <form id="dsarPortalForm">
                <div class="form-group">
                    <label>Full Name <span class="required">*</span></label>
                    <input class="form-control" id="portalName" placeholder="e.g., John Doe" required />
                </div>
                <div class="form-group">
                    <label>Email Address <span class="required">*</span></label>
                    <input class="form-control" id="portalEmail" type="email" placeholder="john@example.com" required />
                </div>
                <div class="form-group">
                    <label>Phone Number</label>
                    <input class="form-control" id="portalPhone" placeholder="+254 701234567" />
                </div>
                <div class="form-group">
                    <label>Request Type <span class="required">*</span></label>
                    <select class="form-control" id="portalType" required>
                        <option value="Access">Access - Request a copy of my personal data</option>
                        <option value="Deletion">Deletion - Request deletion of my personal data</option>
                        <option value="Correction">Correction - Request correction of my personal data</option>
                        <option value="Portability">Portability - Request transfer of my personal data</option>
                        <option value="Objection">Objection - Object to processing of my personal data</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Message <span class="required">*</span></label>
                    <textarea class="form-control" id="portalMessage" placeholder="Please describe your request in detail..." required></textarea>
                </div>

                <div class="privacy-notice">
                    <strong>📋 Privacy Notice:</strong> The information you provide will be used solely to process your data subject request. Your personal data will be retained for 3 months after request completion and then securely deleted or anonymized.
                </div>

                <div class="checkbox-group">
                    <input type="checkbox" id="portalConsent" required />
                    <label for="portalConsent">I confirm that I am the data subject and I have read and agree to the privacy notice above. <span style="color:#f56565;">*</span></label>
                </div>

                <button type="submit" class="btn" id="portalSubmitBtn">📩 Submit Request</button>
            </form>

            <div class="footer">
                <p>Powered by Privy Compliance Management Platform</p>
            </div>
        </div>

        <script>
            const API_URL = 'http://localhost:8000/api';

            function showAlert(message, type = 'success') {
                const alert = document.getElementById('alert');
                alert.textContent = message;
                alert.className = `alert ${type}`;
                setTimeout(() => {
                    alert.className = 'alert';
                }, 6000);
            }

            document.getElementById('dsarPortalForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                const btn = document.getElementById('portalSubmitBtn');
                btn.textContent = '⏳ Submitting...';
                btn.disabled = true;

                const data = {
                    full_name: document.getElementById('portalName').value,
                    email: document.getElementById('portalEmail').value,
                    phone: document.getElementById('portalPhone').value || '',
                    message: document.getElementById('portalMessage').value,
                    request_type: document.getElementById('portalType').value,
                    consent_given: document.getElementById('portalConsent').checked
                };

                try {
                    const res = await fetch(`${API_URL}/dsar`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });

                    if (res.ok) {
                        showAlert('✅ Your request has been submitted successfully! We will respond within 30 days.', 'success');
                        document.getElementById('dsarPortalForm').reset();
                    } else {
                        const err = await res.json();
                        showAlert('❌ Error: ' + (err.detail || 'Submission failed'), 'error');
                    }
                } catch (error) {
                    showAlert('❌ Network error. Please try again.', 'error');
                }

                btn.textContent = '📩 Submit Request';
                btn.disabled = false;
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html, media_type="text/html")

# ============ STATS / DASHBOARD ============
@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    projects = db.query(Project).count()
    ropas = db.query(RoPA).count()
    dpias = db.query(DPIA).count()
    dpia_completed = db.query(DPIA).filter(DPIA.status == "approved").count()
    vendors = db.query(VendorAssessment).count()
    high_risk_vendors = db.query(VendorAssessment).filter(VendorAssessment.risk_rating == "High").count()
    applications = db.query(ApplicationInventory).count()
    third_parties = db.query(ThirdPartyInventory).count()
    dsar_total = db.query(DSAR).count()
    dsar_pending = db.query(DSAR).filter(DSAR.status.in_(["draft", "in_progress"])).count()
    
    return {
        "total_projects": projects,
        "total_ropas": ropas,
        "total_dpias": dpias,
        "dpia_completed": dpia_completed,
        "dpia_compliance_rate": round((dpia_completed / dpias * 100) if dpias > 0 else 0, 2),
        "total_vendors": vendors,
        "high_risk_vendors": high_risk_vendors,
        "total_applications": applications,
        "total_third_parties": third_parties,
        "total_dsar": dsar_total,
        "pending_dsar": dsar_pending
    }

# ============ REPORT ENDPOINTS ============
@app.get("/api/reports/ropa/{project_id}")
def generate_ropa_report(project_id: int, format: str = "html", db: Session = Depends(get_db)):
    ropas = db.query(RoPA).filter(RoPA.project_id == project_id).all()
    project = db.query(Project).filter(Project.id == project_id).first()
    
    if not ropas:
        raise HTTPException(status_code=404, detail="No RoPA records found for this project")
    
    if format == "json":
        return {
            "project": project,
            "ropas": [{
                "id": r.id,
                "processing_activity": r.processing_activity,
                "purpose": r.purpose,
                "lawful_basis": r.lawful_basis,
                "data_subjects": r.data_subjects,
                "personal_data_categories": r.personal_data_categories,
                "recipients": r.recipients,
                "retention_period": r.retention_period,
                "security_measures": r.security_measures,
                "international_transfers": r.international_transfers,
                "controller_name": r.controller_name,
                "processor_name": r.processor_name,
                "status": r.status,
                "created_at": r.created_at
            } for r in ropas]
        }
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"><title>RoPA Report - {project.name}</title>
    <style>body{{font-family:Arial;padding:40px;}} table{{width:100%;border-collapse:collapse;}} th,td{{padding:10px;border:1px solid #ddd;text-align:left;}} th{{background:#f5f5f5;}}</style>
    </head>
    <body>
        <h1>📋 RoPA Report</h1>
        <p><strong>Project:</strong> {project.name} | <strong>Department:</strong> {project.department or 'N/A'}</p>
        <p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}</p>
        <table>
            <thead><tr><th>Activity</th><th>Purpose</th><th>Lawful Basis</th><th>Status</th></tr></thead>
            <tbody>
    """
    for r in ropas:
        html += f"<tr><td>{r.processing_activity}</td><td>{r.purpose[:50] if r.purpose else 'N/A'}</td><td>{r.lawful_basis or 'N/A'}</td><td>{r.status}</td></tr>"
    
    html += """
            </tbody>
        </table>
        <p style="margin-top:40px;color:#94a3b8;font-size:13px;">Privy Compliance Management Platform | Confidential</p>
    </body>
    </html>
    """
    return HTMLResponse(content=html, media_type="text/html")

# ============ RUN ============
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)