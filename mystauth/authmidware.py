import requests
import environ

class MystAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response  #initiate middleware, not special for Myst Auth

    def __call__(self, request, *args, **kwargs):
        if request.path =='/dash/' and request.method == 'GET' and (('usr' in request.GET and 'token' in request.GET) or ('myst_usr' in request.COOKIES and 'myst_token' in request.COOKIES)):  #check if relevant url/cookie params exist
            if 'usr' in request.GET:
                user = request.GET.get('usr')     #get username param
                token = request.GET.get('token')  #get auth token param
            else:
                user = request.COOKIES.get('myst_usr')     #get username cookie
                token = request.COOKIES.get('myst_token')  #get auth token cookie

            request.user = user  #sets request param 'user' to username

            myst_endpoint = "https://mystauth.com/api/v1/user/token/verify/" #Myst Auth Token verify endpoint

            env = environ.Env()            #get environment vars
            environ.Env.read_env()

            myst_id = env("API_ID")        #get api id
            myst_api_key = env("API_KEY")  #get api key

            myst_params = {              #POST parameters
                "id": myst_id,           #your API id, best to retrieve from environment variable or secrets file
                "apiKey": myst_api_key,  #your API key, best to retrieve from environment variable or secrets file
                "usr": user,
                "token": token,
            }

            auth = requests.post(myst_endpoint, json=myst_params)  #make API call, pass params
            auth = auth.json()                                     #get json

            authenticated = auth['success']    #gets 'success' field from json

            if authenticated:                  #checks if 'success': true, token was verified
                request.authenticated = True   #sets request param 'authenticated' to True
                request.token = auth['token']  #sets request param 'token' to the new token from the API call json
                request.info = "Success"
            else:
                request.authenticated = False  #sets request param 'authenticated' to False
                request.info = auth['info']
        else:
            request.authenticated = False      #sets request param 'authenticated' to False
            request.info = "N/A"

        return self.get_response(request)  #returns authenticated request to views.py in Django (the page's controller function)
