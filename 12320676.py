import csv
import bcrypt
import re
import requests
import getpass
import logging


CSV_FILE = 'regno.csv'
MAX_ATTEMPTS = 5
API_KEY = "e2d52b95021ceb8d029dce9f962a10ca"
LOG_FILE = 'system_log.log'  


# Set up logging
logging.basicConfig(filename=LOG_FILE, 
                    level=logging.INFO, 
                    format='%(asctime)s %(levelname)s:%(message)s')


def register_user(email, password, security_question):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([email, hashed_password.decode('utf-8'), security_question])
    logging.info(f"New user registered: {email}")


def load_users():
    users = {}
    try:
        with open(CSV_FILE, mode='r') as file:
            reader = csv.reader(file)
            for row in reader:
                users[row[0]] = (row[1], row[2])
    except FileNotFoundError:
        logging.warning("User file not found. No users loaded.")
    return users


def login_user(email, password):
    users = load_users()
    if email in users:
        hashed_password, _ = users[email]
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            logging.info(f"User {email} logged in successfully.")
            return True
    logging.warning(f"Failed login attempt for user: {email}")
    return False


def validate_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None


def validate_password(password):
    if (len(password) < 8 or
        not any(c.isupper() for c in password) or
        not any(c.islower() for c in password) or
        not any(c.isdigit() for c in password) or
        not any(c in "!@#$%^&*()_+-=[]{}|;':\",.<>?/" for c in password)):
        return False
    return True


def reset_password(email):
    users = load_users()
    if email in users:
        _, security_question = users[email]
        answer = input(f"Security Question: {security_question}\nYour Answer: ")
        new_password = getpass.getpass("Enter a new password: ")  
        if validate_password(new_password):
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            update_password(email, hashed_password.decode('utf-8'))
            print("Password updated successfully.")
            logging.info(f"Password reset successfully for user: {email}")
        else:
            print("Password does not meet criteria.")
            logging.warning(f"Failed password reset for user {email} due to invalid password format.")
    else:
        print("Email not found.")
        logging.warning(f"Password reset failed: {email} not found.")


def update_password(email, new_hashed_password):
    users = load_users()
    with open(CSV_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        for user_email, (hashed_password, question) in users.items():
            if user_email == email:
                writer.writerow([user_email, new_hashed_password, question])
            else:
                writer.writerow([user_email, hashed_password, question])


def login_with_attempts():
    attempts = MAX_ATTEMPTS
    while attempts > 0:
        email = input("Enter your email: ")
        password = getpass.getpass("Enter your password: ")  
        if login_user(email, password):
            print("Login successful!")
            return True
        else:
            attempts -= 1
            print(f"Login failed. {attempts} attempts remaining.")
            logging.warning(f"Login failed for user: {email}. {attempts} attempts left.")
    print("Too many failed attempts. Exiting.")
    logging.error(f"User {email} exceeded maximum login attempts.")
    return False


def get_air_quality(city):
    city_coordinates = {
        "New York": (40.7128, -74.0060),
        "Los Angeles": (34.0522, -118.2437),
        "London": (51.5074, -0.1278),
    }
    
    city = city.title()

    if city not in city_coordinates:
        print(f"Coordinates for {city} not found.")
        logging.error(f"City {city} not found in coordinates.")
        return None, None

    latitude, longitude = city_coordinates[city]

    url = f"http://api.openweathermap.org/data/2.5/air_pollution/history?lat={latitude}&lon={longitude}&start=1606223802&end=1606482999&appid={API_KEY}"

    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        if 'list' in data and data['list']:
            aqi = data['list'][0]['main']['aqi']
            pollutants = data['list'][0]['components']
            logging.info(f"Air quality data retrieved for {city}. AQI: {aqi}")
            return aqi, pollutants
        else:
            logging.warning(f"No air quality data found for {city}.")
            return None, None
    else:
        logging.error(f"Failed to retrieve data for {city}. Status code: {response.status_code}")
        return None, None


def display_air_quality(city):
    aqi, pollutants = get_air_quality(city)
    if aqi is not None:
        print(f"AQI for {city}: {aqi}")
        print("Main Pollutants:")
        for pollutant, value in pollutants.items():
            print(f"{pollutant}: {value} µg/m³")
        provide_health_advice(aqi)
    else:
        print("No data available for the specified city.")


def provide_health_advice(aqi):
    if aqi == 1:
        print("Air quality is Good. Enjoy outdoor activities.")
    elif aqi == 2:
        print("Air quality is Fair. Sensitive individuals should consider reducing outdoor exertion.")
    elif aqi == 3:
        print("Air quality is Moderate. People with respiratory issues should limit outdoor activity.")
    elif aqi == 4:
        print("Air quality is Poor. Everyone should avoid outdoor activities.")
    elif aqi == 5:
        print("Air quality is Very Poor. Stay indoors and use air purifiers if possible.")


def register_new_user():
    email = input("Enter your email: ")
    if validate_email(email):
        password = getpass.getpass("Enter a password: ")
        if validate_password(password):
            security_question = input("Enter a security question : ")
            register_user(email, password, security_question)
            print("User registered successfully.")
        else:
            print("Password does not meet criteria.")
    else:
        print("Invalid email format.")


def main():
    logging.info("MSF Air Quality Monitoring System started.")
    print("Welcome to the MSF Air Quality Monitoring System")
    print("1. Login")
    print("2. Forgot Password")
    print("3. Register")
    print("4. Exit")

    while True:
        action = input("Select an option (1, 2, 3, 4): ").strip()

        if action == '1':
            if login_with_attempts():
                city = input("Enter a city name which you want to see the status of Air Quality: ")
                display_air_quality(city)
            else:
                print("Login failed.")
        elif action == '2':
            email = input("Enter your email to reset password: ")
            reset_password(email)
        elif action == '3':
            register_new_user()
        elif action == '4':
            print("Exiting application. Goodbye!")
            logging.info("MSF Air Quality Monitoring System exited.")
            break
        else:
            print("Invalid selection. Please choose a valid option.")
            logging.warning("Invalid option selected.")


if __name__ == "__main__":
    main()
