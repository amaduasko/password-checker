import requests
import hashlib , sys

try:
    def get_api_data(query): #get api data
        url = 'https://api.pwnedpasswords.com/range/' + query
        res = requests.get(url)

        if res.status_code != 200: #check and rase error if api didn't work properly or bad query
            raise RuntimeError(f'Error during fetch: {res.status_code}, check the api and try again!')
        return res


    def get_password_leaks_count (hashes, hash_to_verify) : #count password leaks
        hashes = (line.split(':') for line in hashes.text.splitlines())
        for h , count in hashes:
            if h == hash_to_verify :
                return count
        return 0

    def check_pwned_api(password): #hash password and encode the result
        hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        head , tail = hashed_password[:5] , hashed_password[5:]
        response = get_api_data(head)

        return get_password_leaks_count(response,tail)


    def main(args) :
        for password in args :
            count = check_pwned_api(password)

            if count :
               print(f'\t{password} was found {count} time... better change your password!!! ')
            else :
                print(f'\t{password} was not found... this one might be safe to use.')
        return print('\tPassword checked succesfuly!!')


    if __name__ == '__main__' :
        sys.exit(main(sys.argv[1:]))

#some error handling
except (requests.exceptions.ConnectionError , RuntimeError, NameError,ValueError) as error:
    print(f'something went wrong, \n This is what happened: {error}')
