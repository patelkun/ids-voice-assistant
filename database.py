from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
import datetime

Base = declarative_base()

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    ip = Column(String)
    attack_type = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.now)

engine = create_engine("sqlite:///ids_history.db")
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

def save_alert(ip, attack_type):
    session = Session()
    alert = Alert(ip=ip, attack_type=attack_type)
    session.add(alert)
    session.commit()
    session.close()

def get_all_alerts():
    session = Session()
    alerts = session.query(Alert).order_by(Alert.timestamp.desc()).all()
    session.close()
    return alerts