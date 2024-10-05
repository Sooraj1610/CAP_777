import csv
import hashlib
import re
import requests
import logging
import os


logging.basicConfig(filename='app.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def validate_password(password):
    if len(password) < 8:
        print("Password must be at least 8 characters long.")
        logging.warning("Password length less than 8 characters.")
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("Password must contain at least one special character.")
        logging.warning("Password missing special character.")
        return False
    return True


def validate_email(email):
    return re.match(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', email)


user_credentials = {}
if os.path.exists('regno.csv'):
    with open('regno.csv', 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            user_credentials[row['email']] = {
                'password': row['password'],
                'security_question': row['security_question'],
                'security_answer': row['security_answer']
            }


def register_user():
    email = input("Enter your email: ")


    if not validate_email(email):
        print("Invalid email format. Try again.")
        logging.warning("Invalid email format during registration.")
        return
    

    if email in user_credentials:
        print("This email is already registered. Try logging in.")
        logging.info(f"Registration attempt with already registered email: {email}")
        return

    
    while True:
        password = input("Create your password: ")
        if validate_password(password):
            break

    hashed_password = hash_password(password)

    security_question = input("Enter a security question (e.g., What is your pet's name?): ")
    security_answer = input(f"Answer for your security question: ")


    user_credentials[email] = {
        'password': hashed_password,
        'security_question': security_question,
        'security_answer': security_answer
    }

   
    with open('regno.csv', 'a', newline='') as csvfile:
        fieldnames = ['email', 'password', 'security_question', 'security_answer']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

      
        if os.stat('regno.csv').st_size == 0:
            writer.writeheader()

        writer.writerow({
            'email': email,
            'password': hashed_password,
            'security_question': security_question,
            'security_answer': security_answer
        })

    print("Registration successful! You can now log in.")
    logging.info(f"New user registered: {email}")

def reset_password():
    email = input("Enter your registered email: ")

    if email not in user_credentials:
        print("Email not registered.")
        logging.warning(f"Password reset attempted for unregistered email: {email}")
        return
    
    print(f"Security question: {user_credentials[email]['security_question']}")
    answer = input("Answer: ")

    if answer == user_credentials[email]['security_answer']:
      
        while True:
            new_password = input("Enter your new password: ")
            if validate_password(new_password):
                user_credentials[email]['password'] = hash_password(new_password)
                print("Password reset successful.")
                logging.info(f"Password reset for user: {email}")

               
                with open('regno.csv', 'w', newline='') as csvfile:
                    fieldnames = ['email', 'password', 'security_question', 'security_answer']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    for user_email, details in user_credentials.items():
                        writer.writerow({
                            'email': user_email,
                            'password': details['password'],
                            'security_question': details['security_question'],
                            'security_answer': details['security_answer']
                        })
                break
    else:
        print("Incorrect answer to the security question.")
        logging.warning(f"Password reset failed due to incorrect answer for: {email}")

def login():
    attempts = 5
    while attempts > 0:
        email = input("Enter your email: ")
        password = input("Enter your password: ")

        if email in user_credentials and user_credentials[email]['password'] == hash_password(password):
            print("Login successful!")
            logging.info(f"User logged in: {email}")
            return email  
        else:
            attempts -= 1
            print(f"Invalid credentials. You have {attempts} attempts left.")
            logging.warning(f"Failed login attempt for: {email}")
    
    print("Too many failed attempts. Please try again later.")
    logging.error("Maximum login attempts reached.")
    return None


def get_news_headlines(email):
    keyword = input("Enter a keyword to fetch news: ")
    api_key = "f3461f9a09f94883818ddd3ba2512727"
    url = f"https://newsapi.org/v2/top-headlines?q={keyword}&apiKey={api_key}"

    try:
        response = requests.get(url)
        response.raise_for_status() 
        data = response.json()

        if 'articles' in data and len(data['articles']) > 0:
            articles = data['articles'][:5]
            print(f"\nTop 5 news articles for '{keyword}':")
            for article in articles:
                print(f"{article['title']} - {article['source']['name']}")
            logging.info(f"User {email} fetched top 5 news articles for topic: {keyword}")
        else:
            print(f"No news articles found for '{keyword}'.")
            logging.warning(f"No news articles found for topic: {keyword}")
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        logging.error(f"HTTP error during API request for user {email}: {http_err}")
    except requests.exceptions.ConnectionError:
        print("Error: Network connection issue. Please check your internet connection.")
        logging.error(f"Network connection issue during API request for user {email}.")
    except Exception as err:
        print(f"An error occurred: {err}")
        logging.error(f"Unexpected error during API request for user {email}: {err}")


def main():
    while True:
        print("\n--- News Headlines Console Application ---")
        print("1. Register")
        print("2. Login")
        print("3. Reset Password")
        print("4. Exit")
        
        choice = input("Choose an option (1-4): ")

        if choice == '1':
            register_user()
        elif choice == '2':
            email = login()
            if email:
                get_news_headlines(email)
        elif choice == '3':
            reset_password()
        elif choice == '4':
            print("Exiting the application. Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
