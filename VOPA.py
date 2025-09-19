from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import List
from pydantic import BaseModel

# ======================================================
# -------------DATABASE SETUP--------------------------
# ======================================================
DATABASE_URL = "sqlite:///./vschool.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ======================================================
# -----------------MODELS-----------------------------
# ======================================================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String)  # "teacher" or "student"


class Course(Base):
    __tablename__ = "courses"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    teacher_id = Column(Integer, ForeignKey("users.id"))


class Lesson(Base):
    __tablename__ = "lessons"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    course_id = Column(Integer, ForeignKey("courses.id"))


class Assignment(Base):
    __tablename__ = "assignments"
    id = Column(Integer, primary_key=True, index=True)
    lesson_id = Column(Integer, ForeignKey("lessons.id"))
    student_id = Column(Integer, ForeignKey("users.id"))
    completed = Column(Boolean, default=False)


Base.metadata.create_all(bind=engine)


# ======================================================
# ----------------AUTH & SECURITY----------------------
# ======================================================
SECRET_KEY = "your_secret_key"  # change in production!
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_db():
    """Dependency to get DB session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Password utils
def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)


def hash_password(password):
    return pwd_context.hash(password)


# JWT utils
def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Extract user from JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# ======================================================
# -------------------SCHEMAS----------------------------
# ======================================================
class UserCreate(BaseModel):
    username: str
    password: str
    role: str  # "teacher" or "student"


class UserResponse(BaseModel):
    id: int
    username: str
    role: str

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class CourseCreate(BaseModel):
    title: str


class CourseResponse(BaseModel):
    id: int
    title: str
    teacher_id: int

    class Config:
        orm_mode = True


class LessonCreate(BaseModel):
    title: str
    course_id: int


class LessonResponse(BaseModel):
    id: int
    title: str
    course_id: int

    class Config:
        orm_mode = True


class AssignmentCreate(BaseModel):
    lesson_id: int
    student_id: int


class AssignmentResponse(BaseModel):
    id: int
    lesson_id: int
    student_id: int
    completed: bool

    class Config:
        orm_mode = True


# ======================================================
# -----------------FASTAPI APP-------------------------
# ======================================================
app = FastAPI(title="V-School API")


# ------------------------------------------------------
# ------------AUTHENTICATION ENDPOINTS------------------
# ------------------------------------------------------
@app.post("/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")

    new_user = User(username=user.username,
                    hashed_password=hash_password(user.password),
                    role=user.role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_data = {"sub": user.username}
    access_token = create_access_token(token_data)
    return {"access_token": access_token, "token_type": "bearer"}


# ---------------------------------------------------------
# ----------------------COURSE ENDPOINTS-------------------
# ---------------------------------------------------------
@app.post("/api/courses", response_model=CourseResponse)
def create_course(course: CourseCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can create courses")

    new_course = Course(title=course.title, teacher_id=user.id)
    db.add(new_course)
    db.commit()
    db.refresh(new_course)
    return new_course


# -------------------------------------------------------------------
# --------------------------LESSON ENDPOINTS-------------------------
# -------------------------------------------------------------------
@app.post("/api/lessons", response_model=LessonResponse)
def create_lesson(lesson: LessonCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can add lessons")

    course = db.query(Course).filter_by(id=lesson.course_id, teacher_id=user.id).first()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found or not owned by you")

    new_lesson = Lesson(title=lesson.title, course_id=lesson.course_id)
    db.add(new_lesson)
    db.commit()
    db.refresh(new_lesson)
    return new_lesson


# ---------------------------------------------------------------------
# -------------------ASSIGNMENT ENDPOINTS------------------------------
# ---------------------------------------------------------------------
@app.post("/api/assignments", response_model=AssignmentResponse)
def assign_lesson(data: AssignmentCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can assign lessons")

    assignment = Assignment(lesson_id=data.lesson_id, student_id=data.student_id)
    db.add(assignment)
    db.commit()
    db.refresh(assignment)
    return assignment


@app.get("/api/assignments/me", response_model=List[AssignmentResponse])
def my_assignments(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can view their assignments")

    return db.query(Assignment).filter_by(student_id=user.id, completed=False).all()


@app.put("/api/assignments/{assignment_id}/complete")
def mark_complete(assignment_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    assignment = db.query(Assignment).filter_by(id=assignment_id, student_id=user.id).first()
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")

    assignment.completed = True
    db.commit()
    return {"message": "Lesson marked as complete"}


@app.get("/api/teacher/assignments", response_model=List[AssignmentResponse])
def teacher_assignments(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can view this")

    return db.query(Assignment).all()
