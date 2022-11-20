from fastapi import FastAPI, Depends, HTTPException, File, status
from PIL import Image
import PIL.ImageOps
from fastapi.security import HTTPBasic, OAuth2PasswordBearer, OAuth2PasswordRequestForm
import datetime
from pydantic import BaseModel
import io
from fastapi.responses import StreamingResponse

# pip install python-multipart
# pip install Pillow


def prime_number(number):
    if number == 1:
        return "This is not a prime number"
    elif 2 < number < 98989798676:
        for i in range(2, number):
            if number % i == 0:
                return "This is not a prime number"
            else:
                return "This is a prime number"
    else:
        return 'Out of range'


def invert_function(img_file):
    image = Image.open(io.BytesIO(img_file))
    inverted_image = PIL.ImageOps.invert(image)
    ready = io.BytesIO()
    inverted_image.save(ready, format='JPEG')
    ready.seek(0)
    return ready


fake_users_db = {
    "grupa1": {
        "username": "grupa1",
        "hashed_password": "dontbesuspiciousinformatyka",
    },
}

security = HTTPBasic()


app = FastAPI()


@app.get('/prime/{n}')
async def check_if_prime(n):
    """Check if number is prime. It shouldn't be greater 9223372036854775807"""
    if n.isnumeric():
        number = int(n)
        return prime_number(number)
    else:
        return "Not an integer"


@app.post("/invert/picture/")
async def get_image_file(path: bytes = File(...)):
    """Invert uploaded photo"""
    try:
        response = StreamingResponse(
            content=invert_function(path),
            status_code=status.HTTP_200_OK,
            media_type="image/jpeg",)
        return response
    except FileNotFoundError:
        raise HTTPException(detail="File not found.", status_code=status.HTTP_404_NOT_FOUND)


def fake_hash_password(password: str):
    return "dontbesuspicious" + password


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class User(BaseModel):
    username: str


class UserInDB(User):
    hashed_password: str


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def fake_decode_token(token):
    user = get_user(fake_users_db, token)
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


@app.post("/time")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Check the current date and time by logging in. User: grupa1, password: informatyka"""
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    return datetime.datetime.utcnow().strftime("Day: %d.%m.%Y - %A; Time: %H:%M")
