"""core.DB
File: db.py
Author: LordLumineer
Date: 2024-05-03

Purpose: This file handles the database communication and connection.
"""

import os
import io
import json
import socket
import shutil
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from PIL import Image
from bson import ObjectId
from pymongo import MongoClient, errors

from models import FetchedUserInDB, UserInDB, AdminUser
from core.engine import engine
from core.config import settings, log
from core.email import send_db_alert_email

client: MongoClient
UsersDB: list
collection: list

# ~~~~ Utils Functions ~~~~ #


async def startup_auth_db():  # bool
    """Handles the startup of the MongoDB connection and database creation.
    If the database needs to be created, it will create the collections and load the backup data.
    It initiates the backup job for the database.
    And defines the global variables for the MongoDB connection and collections.

    Returns:
        bool: Returns True if the connection was successful, False otherwise (Is used in the startup of the main program to detect if it is running).
    """
    log.info("Connecting to MongoDB")
    global client
    global UsersDB
    global collection
    db_host = settings.DATABASE_HOST
    db_port = settings.DATABASE_PORT
    db_root_user = settings.DATABASE_USERNAME
    db_root_pwd = settings.DATABASE_PASSWORD

    connection_uri = f"mongodb://{db_root_user}:{db_root_pwd}@{db_host}:{db_port}"
    client = MongoClient(connection_uri)
    if not await is_mongodb_running():
        log.error(f"Failed to connect to MongoDB with the provided Host {db_host}")
        db_host = socket.gethostbyname(socket.gethostname())
        log.info(
            f"Trying to connect to MongoDB with the automated fetched Host {db_host}"
        )
        connection_uri = f"mongodb://{db_root_user}:{db_root_pwd}@{db_host}:{db_port}"
        client = MongoClient(connection_uri)
        if not await is_mongodb_running():
            log.error(
                f"Failed to connect to MongoDB with the automated fetched Host {db_host}"
            )
            return False

    log.success("Connected to MongoDB")

    engine.add_job(
        func=backup_database,
        args=["users"],
        trigger="cron",
        hour=settings.DATABASE_BACKUP_TIME[0],
        minute=settings.DATABASE_BACKUP_TIME[1],
        name="Database Backup Job",
        id="database_backup_job",
        replace_existing=True,
    )

    latest_backup = None
    if await create_database_if_not_exists("users"):
        if not await create_collection_if_not_exists("users", "eventkitstream_users"):
            if not latest_backup:
                latest_backup = await latest_backup_folder()
            await load_collection_backup("users", "eventkitstream_users", latest_backup)
        if not await create_collection_if_not_exists("users", "profile_pictures"):
            if not latest_backup:
                latest_backup = await latest_backup_folder()
            await load_collection_backup("users", "profile_pictures", latest_backup)
        if not await create_collection_if_not_exists("users", "admin_users"):
            if not latest_backup:
                latest_backup = await latest_backup_folder()
            await load_collection_backup("users", "admin_users", latest_backup)
    else:
        if not latest_backup:
            latest_backup = await latest_backup_folder()
        await load_backup("users", latest_backup)
    UsersDB = client["users"]
    collection = UsersDB["eventkitstream_users"]
    return True


async def disconnect():  # bool
    """Function to disconnect from the MongoDB cleanly.
    It will also backup the database before disconnecting and stopping the backup job.

    Returns:
        bool: Returns True if the disconnection was successful, False otherwise.
    """
    log.info("Disconnecting from MongoDB")
    try:
        if "database_backup_job" in engine.get_jobs():
            engine.remove_job(job_id="database_backup_job")
        await backup_database("users")
        client.close()
    except (errors.PyMongoError, errors.ServerSelectionTimeoutError):
        log.error("Failed to disconnect from MongoDB, it may be already disconnected")
        return False

    log.success("Disconnected from MongoDB")
    return True


async def is_mongodb_running():  # bool
    """Simple function to check if the MongoDB is running.
    If it is not running, it will send an email alert to the admin.

    Returns:
        bool: Returns True if the MongoDB is running, False otherwise.
    """
    try:
        client.server_info()
        return True
    except errors.ServerSelectionTimeoutError:
        log.critical("Failed to connect to MongoDB, please check if it's running")
        await send_db_alert_email()
        return False


async def latest_backup_folder():  # str | None
    """Simple helper function to get the latest backup folder.

    Returns:
        str | None: Returns the path to the latest backup folder, None if no backup folders are found.
    """
    backup_dir = settings.DATABASE_BACKUP_PATH
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    backup_folders = os.listdir(backup_dir)
    now = datetime.now(timezone.utc)
    oldest = now - timedelta(days=settings.DATABASE_BACKUP_RETENTION)
    for folder in backup_folders:
        timestamp = int(folder.split("_")[0])
        date = datetime.fromtimestamp(timestamp, timezone.utc)
        if date < oldest and (folder != "1008720000_EXAMPLE_backup"):
            log.info(f"Removing old backup folder '{folder}'")
            shutil.rmtree(os.path.join(backup_dir, folder))

    backup_folders = os.listdir(backup_dir)
    if backup_folders:
        return os.path.join(backup_dir, sorted(backup_folders)[-1])
    log.warning("No backup folders found")
    return None


# Database Functions


async def create_database_if_not_exists(db_name: str):  # bool
    """Checks if a database exists in MongoDB, if it does not exist, it will create it.

    Args:
        db_name (str): The name of the database to check.

    Returns:
        bool: Returns True if the database exists, False otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        if db_name not in client.list_database_names():
            log.warning(f"Database '{db_name}' does not exist. Creating...")
            new_db = client[db_name]
            log.success(f"Database '{new_db.name}' created successfully")
            return False
        log.success(f"Database '{db_name}' already exists")
        return True
    except Exception:
        log.error(f"Failed to check the existence of the database '{db_name}'")
        return None


async def backup_database(db_name: str):  # str | None
    """Backup the database to a JSON file (the profile pictures are saved as a file for better readability).

    Args:
        db_name (str): The name of the database to backup.

    Returns:
        str | None: Returns the path to the backup file if successful, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        now = int(datetime.now(timezone.utc).timestamp())
        backup_path = os.path.join(
            settings.DATABASE_BACKUP_PATH, f"{now}_{db_name}_backup"
        )
        if not os.path.exists(backup_path):
            os.makedirs(backup_path)

        db = client[db_name]
        backup_data = {}
        for collection_name in db.list_collection_names():
            log.info(f"Backing up collection '{collection_name}'")
            backup_data[collection_name] = []
            if collection_name == "profile_pictures":
                folder_path = os.path.join(backup_path, f"{collection_name}")
                if not os.path.exists(folder_path):
                    os.makedirs(folder_path)
                for document in db[collection_name].find():
                    metadata = {
                        "_id": str(document["_id"]),
                        "name": document["name"],
                    }
                    image = Image.open(io.BytesIO(document["image"]))
                    file_path = os.path.join(
                        folder_path, f"{metadata['_id']}_{metadata['name']}"
                    ).replace("\\", "/")
                    image.save(file_path, format=image.format, **metadata)
                    backup_data[collection_name].append(
                        {"metadata": metadata, "file_path": file_path}
                    )
                continue

            for document in db[collection_name].find():
                document["_id"] = str(document["_id"])
                backup_data[collection_name].append(document)
        backup_file = os.path.join(
            backup_path, f"{db_name}_{'eventkitstream_users'}_backup.json"
        )

        try:
            with open(backup_file, "x", encoding="utf-8") as file:
                json.dump(backup_data, file, indent=2)
        except (
            FileExistsError,
            FileNotFoundError,
            json.JSONDecodeError,
        ) as e:
            errors_msg = (
                f"Failed to create backup file '{backup_file}' | With error: {e}"
            )
            log.error(errors_msg)
            return None
        log.success(
            f"Backup of database '{db_name}' completed successfully to '{backup_file}'"
        )
        return backup_file

    except Exception:
        log.error(f"Failed to backup the database '{db_name}'")
        return None


async def load_backup(db_name: str, backup_folder: str):  # True | None
    """Load the backup data into the database.

    Args:
        db_name (str): The name of the database to load the backup data into.
        backup_folder (str): The path to the backup folder to use.

    Returns:
        bool: Returns True if the backup data was loaded successfully, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        db = client[db_name]
        try:
            backup_file = os.path.join(
                backup_folder,
                f"{db_name}_{'eventkitstream_users'}_backup.json",
            )
            with open(backup_file, "r", encoding="utf-8") as file:
                backup_data = json.load(file)
                for collection_name in backup_data.keys():
                    for document in backup_data[f"{collection_name}"]:
                        if collection_name == "profile_pictures":
                            image = Image.open(document["file_path"])
                            img_byte_arr = io.BytesIO()
                            image.save(img_byte_arr, format=image.format)
                            img_byte_arr = img_byte_arr.getvalue()
                            document["_id"] = ObjectId(document["metadata"]["_id"])
                            document["name"] = document["metadata"]["name"]
                            document["image"] = img_byte_arr
                            document.pop("file_path")
                            document.pop("metadata")
                            continue
                        document["_id"] = ObjectId(document["_id"])
        except FileNotFoundError:
            log.error(f"Backup file '{backup_file}' not found")
            return None

        for collection_name, documents in backup_data.items():
            collection = db[collection_name]
            collection.insert_many(documents)
        log.success(
            f"Backup data from '{backup_file}' loaded into database '{db_name}' successfully"
        )
        return True

    except Exception:
        log.error(f"Failed to load backup data into database '{db_name}'")
        return None


# Collection Functions


async def create_collection_if_not_exists(
    db_name: str, collection_name: str
):  # bool | None
    """Checks if a collection exists in a database, if it does not exist, it will create it.

    Args:
        db_name (str): The name of the database to check.
        collection_name (str): The name of the collection to check.

    Returns:
        bool: Returns True if the collection exists, False otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        if collection_name not in client[db_name].list_collection_names():
            log.warning(f"Collection '{collection_name}' does not exist. Creating...")
            new_collection = client[db_name][collection_name]
            log.success(f"Collection '{new_collection.name}' created successfully")
            return False
        log.success(f"Collection '{collection_name}' already exists")
        return True
    except Exception:
        log.error(
            f"Failed to check the existence of the collection '{collection_name}'"
        )
        return None


async def load_collection_backup(
    db_name: str, collection_name: str, backup_folder: str
):  # True | None
    """Load the part of the backed-up data into the collection.

    Args:
        db_name (str): The name of the database to load the backup data into.
        collection_name (str): The name of the collection to load the backup data into.
        backup_folder (str): The path to the backup folder to use.

    Returns:
        bool: Returns True if the backup data was loaded successfully, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        backup_file = os.path.join(
            backup_folder,
            f"{db_name}_{'eventkitstream_users'}_backup.json",
        )
        db = client[db_name]
        collection = db[collection_name]
        try:
            with open(backup_file, "r", encoding="utf-8") as file:
                backup_data = json.load(file)
                for document in backup_data[f"{collection_name}"]:
                    if collection_name == "profile_pictures":
                        image = Image.open(document["file_path"])
                        img_byte_arr = io.BytesIO()
                        image.save(img_byte_arr, format=image.format)
                        img_byte_arr = img_byte_arr.getvalue()
                        document["_id"] = ObjectId(document["metadata"]["_id"])
                        document["name"] = document["metadata"]["name"]
                        document["image"] = img_byte_arr
                        document.pop("file_path")
                        document.pop("metadata")
                        continue
                    document["_id"] = ObjectId(document["_id"])
        except FileNotFoundError:
            log.error(f"Backup file '{backup_file}' not found")
            return None
        if backup_data[f"{collection_name}"] == []:
            log.warning(f"Backup data {collection_name} from '{backup_file}' is empty")
            return None
        collection.insert_many(backup_data[f"{collection_name}"])
        log.success(
            f"Backup data from '{backup_file}' loaded into collection '{collection_name}' successfully"
        )
        return True
    except Exception:
        log.error(
            f"Failed to load backup data into collection '{collection_name}' in database '{db_name}'"
        )
        return None


# ~~~~ User Functions ~~~~ #


async def get_new_local_uuid():  # str
    """Generates a new UUID for a local user.

    Returns:
        str: Returns the new UUID for the local user.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        is_unique_uuid = False
        while not is_unique_uuid:
            user_id = str(uuid4())
            is_user = collection.find_one({"local_id": user_id})
            if not is_user:
                is_unique_uuid = True
                return user_id
        return None
    except Exception:
        log.error("Failed to generate a new UUID")
        return None


async def fetch_local_user_by_name(username: str):  # UserInDB | None
    """Fetches a local user by their username.

    Args:
        username (str): The username of the local user to fetch.

    Returns:
        UserInDB: Returns the full user minus the UUID if the user is found, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        user = collection.find_one({"local_username": username})
        if user:
            cleaned_user = FetchedUserInDB(**user)
            cleaned_user.uuid = str(user["_id"])
            return cleaned_user
        log.debug(f"Local User with username [{username}] not found")
        return None
    except Exception:
        log.error(f"Failed to fetch local user by username [{username}]")
        return None


async def fetch_local_user_by_email(email: str):  # UserInDB | None
    """Fetches a local user by their email.

    Args:
        email (str): The email of the local user to fetch.

    Returns:
        UserInDB: Returns the full user minus the UUID if the user is found, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        user = collection.find_one({"local_email": email})
        if user:
            cleaned_user = FetchedUserInDB(**user)
            cleaned_user.uuid = str(user["_id"])
            return cleaned_user
        log.debug(f"Local User with email [{email}] not found")
        return None
    except Exception:
        log.error(f"Failed to fetch local user by email [{email}]")
        return None


async def fetch_twitch_user_by_email(email: str):  # UserInDB | None
    """Fetches a Twitch user by their email.

    Args:
        email (str): The email of the Twitch user to fetch.

    Returns:
        UserInDB: Returns the full user minus the UUID if the user is found, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        user = collection.find_one({"twitch_email": email})
        if user:
            cleaned_user = FetchedUserInDB(**user)
            cleaned_user.uuid = str(user["_id"])
            return cleaned_user
        log.debug(f"Twitch User with email [{email}] not found")
        return None
    except Exception:
        log.error(f"Failed to fetch Twitch user by email [{email}]")
        return None


async def fetch_twitch_user_by_id(twitch_id: str):  # UserInDB | None
    """Fetches a Twitch user by their ID.

    Args:
        twitch_id (str): The ID of the Twitch user to fetch.

    Returns:
        UserInDB: Returns the full user minus the UUID if the user is found, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        user = collection.find_one({"twitch_id": twitch_id})
        if user:
            cleaned_user = FetchedUserInDB(**user)
            cleaned_user.uuid = str(user["_id"])
            return cleaned_user
        log.debug(f"Twitch User with ID [{twitch_id}] not found")
        return None
    except Exception:
        log.error(f"Failed to fetch Twitch user by ID [{twitch_id}]")
        return None


async def fetch_google_user_by_email(email: str):  # UserInDB | None
    """Fetches a Google user by their email.

    Args:
        email (str): The email of the Google user to fetch.

    Returns:
        UserInDB: Returns the full user minus the UUID if the user is found, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        user = collection.find_one({"google_email": email})
        if user:
            cleaned_user = FetchedUserInDB(**user)
            cleaned_user.uuid = str(user["_id"])
            return cleaned_user
        log.debug(f"Google User with email [{email}] not found")
        return None
    except Exception:
        log.error(f"Failed to fetch Google user by email [{email}]")
        return None


async def fetch_google_user_by_id(google_id: str):  # UserInDB | None
    """Fetches a Google user by their ID.

    Args:
        google_id (str): The ID of the Google user to fetch.

    Returns:
        UserInDB: Returns the full user minus the UUID if the user is found, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        user = collection.find_one({"google_id": google_id})
        if user:
            cleaned_user = FetchedUserInDB(**user)
            cleaned_user.uuid = str(user["_id"])
            return cleaned_user
        log.debug(f"Google User with ID [{google_id}] not found")
        return None
    except Exception:
        log.error(f"Failed to fetch Google user by ID [{google_id}]")
        return None


async def create_user(user: UserInDB):  # FetchedUserInDB | None
    """Creates a new user in the database.

    Args:
        user (UserInDB): The user to create in the database.

    Returns:
        UserInDB: Returns the full user created WITH the UUID, if the user is created, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        db_id = collection.insert_one(user.model_dump()).inserted_id
        if not db_id:
            log.error(f"Failed to create user [{user.local_username}]")
            return None
        cleaned_user = FetchedUserInDB(**user.model_dump())
        cleaned_user.uuid = str(db_id)
        log.success(f"User [{user.full_name}] created successfully")
        # TODO: Create EventKitStream user database with default collections with values -> BackgroundTask -> http request to eventkit
        return cleaned_user
    except Exception:
        log.error(f"Failed to create user: {user.full_name}")
        return None


async def fetch_user_by_id(uuid: str):  # UserInDB | None
    """Fetches a user by their ID.

    Args:
        uuid (str): The ID of the user to fetch.

    Returns:
        UserInDB: Returns the full user minus the UUID if the user is found, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        user = collection.find_one({"_id": ObjectId(uuid)})
        if user:
            cleaned_user = FetchedUserInDB(**user)
            cleaned_user.uuid = str(user["_id"])
            return cleaned_user
        log.debug(f"User with ID [{uuid}] not found")
        return None
    except Exception:
        log.error(f"Failed to fetch user by ID [{uuid}]")
        return None


async def update_user_by_id(user: FetchedUserInDB):  # FetchedUserInDB | None
    """Updates a user in the database.

    Args:
        user (FetchedUserInDB): The user to update in the database.

    Returns:
        UserInDB: Returns the full user WITH the UUID, if the user is updated, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        if not user.uuid:
            log.warning("The user does not have an ID")
            return None
        user_for_db = UserInDB(**user.model_dump())
        acknowledged = collection.update_one(
            {"_id": ObjectId(user.uuid)}, {"$set": user_for_db.model_dump()}
        ).acknowledged
        if not acknowledged:
            log.error(f"Failed to update user [{user.full_name}]")
            return None
        log.success(f"User [{user.full_name}] updated successfully")
        # TODO: Update EventKitStream user database
        return user
    except Exception:
        log.error(f"Failed to update user [{user.full_name}]")
        return None


async def remove_user_by_id(uuid: str, is_disabled=False):  # bool
    """Removes a user from the database.

    Args:
        uuid (str): The ID of the user to remove.
        is_disabled (bool, optional): If the user is disabled, defaults to False.

    Returns:
        bool: Returns True if the user is removed, False otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        if not is_disabled:
            user = await fetch_user_by_id(uuid)
            if not user:
                log.error(f"User with ID [{uuid}] not found")
            else:
                user.disabled = True
                user = await update_user_by_id(user)
                if not user:
                    log.error(f"Failed to disable user [{user.full_name}]")
                else:
                    is_disabled = True
        acknowledged = collection.delete_one({"_id": ObjectId(uuid)}).acknowledged
        if acknowledged and is_disabled:
            log.success(f"User with ID [{uuid}] removed successfully")
            # TODO: Remove EventKitStream user database
            return True
        log.error(f"Failed to remove user with ID [{uuid}]")
        return False
    except Exception:
        log.error(f"Failed to remove user by ID [{uuid}]")
        return False


# ~~~~ Profile Picture Functions ~~~~ #
async def save_pfp(file_name: str, image: bytes, image_id: str = None):  # str | None
    """Saves a profile picture to the database.

    Args:
        file_name (str): filename of the image.
        image (bytes): image data.
        image_id (str, optional): ID of the image to update, defaults to None.

    Returns:
        str: ID of the image saved/updated, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        collection = UsersDB["profile_pictures"]
        if not image_id:
            image_id = collection.insert_one(
                {"name": file_name, "image": image}
            ).inserted_id
            return str(image_id)
        result = collection.update_one(
            {"_id": ObjectId(image_id)},
            {"$set": {"name": file_name, "image": image}},
        )
        if result.raw_result.get("updatedExisting"):
            log.success(
                f"Profile Picture [{image_id}:{file_name}] saved/updated successfully"
            )
            return str(image_id)
        return None
    except Exception:
        log.error("Failed to save profile picture")
        return None


async def fetch_pfp(image_id: str):  # dict | None
    """Fetches a profile picture from the database.

    Args:
        image_id (str): ID of the image to fetch.
    Returns:
        bytes: Image data, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        collection = UsersDB["profile_pictures"]
        return collection.find_one({"_id": ObjectId(image_id)})
    except Exception:
        log.error(f"Failed to fetch profile picture with ID [{image_id}]")
        return None


async def remove_pfp(image_id: str):  # bool
    """Removes a profile picture from the database.

    Args:
        image_id (str): ID of the image to remove.

    Returns:
        bool: Returns True if the image is removed, False otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        collection = UsersDB["profile_pictures"]
        if collection.delete_one({"_id": ObjectId(image_id)}).acknowledged:
            log.success(f"Profile Picture [{image_id}] removed successfully")
            return True
        log.warning(f"Profile Picture [{image_id}] not found")
    except Exception:
        log.error(f"Failed to remove profile picture with ID [{image_id}]")
        return False


# ~~~~ Admin Functions ~~~~ #
async def create_admin_user(user: AdminUser):  # AdminUser | None
    """Creates a new admin user in the database. (DO NOT USE YET)

    Args:
        user (AdminUser): _description_

    Raises:
        Exception: "DO NO USE"

    Returns:
        AdminUser: {
            "username": str,
            "hashed_password": str,
        }
    """
    # try:
    #     if not await is_mongodb_running():
    #         raise Exception("MongoDB is not running")
    #     collection = UsersDB["admin_users"]
    #     collection.insert_one(user.model_dump())
    #     log.success(f"Admin User [{user.username}] created successfully")
    #     return user
    # except Exception:
    #     log.error(f"Failed to create admin user: {user}")
    #     return None
    raise NotImplementedError("DO NOT USE")


async def fetch_admin_user(username: str):  # AdminUser | None
    """Fetches an admin user by their username.

    Args:
        username (str): The username of the admin user to fetch.

    Returns:
        AdminUser: {
            "username": str,
            "hashed_password": str,
        }
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        collection = UsersDB["admin_users"]
        user = collection.find_one({"username": username})
        if user:
            return AdminUser(**user)
        log.debug(f"Admin User with username [{user.username}] not found")
        return None
    except Exception:
        log.error(f"Failed to fetch admin user by username [{user.username}]")
        return None


async def fetch_all_emails():  # list | None
    """Fetches all emails from the database.

    Returns:
        str[]: Returns a list of all emails if successful, None otherwise.
    """
    try:
        if not await is_mongodb_running():
            raise Exception("MongoDB is not running")
        collection = UsersDB["eventkitstream_users"]
        fields_to_include = [
            "login_method",
            "local_email",
            "twitch_email",
            "google_email",
        ]
        projection = {field: 1 for field in fields_to_include}
        projection["_id"] = 0
        result = collection.find({}, projection)
        emails = []
        for user in result:
            match user["login_method"]:
                case "local":
                    emails.append(user["local_email"])
                case "twitch":
                    emails.append(user["twitch_email"])
                case "google":
                    emails.append(user["google_email"])
                case _:
                    log.error(f"Unknown login method {user['login_method']}")
                    return None
        return emails
    except Exception:
        log.error("Failed to fetch all emails")
        return None
