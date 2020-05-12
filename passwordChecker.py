# the most secure way to check if your password has been hacked
# check if your password is secure with haveibeenpwned api
import requests # It allows us to make a request
# built in module hashlib
import hashlib
import sys

def request_api_data(query):   
    # this is a tecnique used to check all the hashed passwords
    url= 'https://api.pwnedpasswords.com/range/' + query
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, check the API and try again..')
    return response

def get_password_leaks_count(hashes, has_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == has_to_check:
            return count
    return 0

# check the pawned api
def pwned_api_check(password):
    # exdigest() change the value into a decimal digits string
    # check password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times, you should change your password..')
        else:
            print(f'{password} was not found carry on!!')
    return 'DONE'

if __name__=='__main__':
    sys.exit(main(sys.argv[1:]))