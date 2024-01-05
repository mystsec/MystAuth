import requests
import environ

class MystAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response  #initiate middleware, not special for Myst Auth

    def __call__(self, request, *args, **kwargs):
        if not request.path == '/dash' and not request.path == '/dash/': #check url path of request, apply auth middleware to dashboard only
            return self.get_response(request)
        else:
            if request.method == 'GET' and 'usr' in request.GET and 'token' in request.GET:  #check if relevant url params exist
                user = request.GET.get('usr')  #get username param
                token = request.GET.get('token')  #get auth token param

                myst_endpoint = "https://mystauth.com/api/v1/user/token/verify/" #Myst Auth Token verify endpoint

                env = environ.Env()    #get environment vars
                environ.Env.read_env()

                myst_id = env("API_ID") #get api id
                myst_api_key = env("API_KEY") #get api key

                myst_params = {  #POST parameters
                    "id": myst_id,  #your API id, best to retrieve from environment variable or secrets file
                    "apiKey": myst_api_key,  #your API key, best to retrieve from environment variable or secrets file
                    "usr": user,
                    "token": token,
                }

                auth = requests.post(myst_endpoint, json=myst_params)  #make API call, pass params
                auth = auth.json()  #get json

                #getOrigin = Origin.objects.get(uid = myst_id)
                #oid = getOrigin.oid

                #auth = authenticateToken(oid, user, token)

                authenticated = auth['success']  #gets 'success' field from json

                if authenticated:  #checks if 'success': true, token was verified
                    request.authenticated = True  #sets request param 'authenticated' to True
                    request.token = auth['token']  #sets request param 'token' to the new token from the API call json
                else:
                    request.authenticated = False #sets request param 'authenticated' to False
                    request.info = auth['info']
            else:
                request.authenticated = False #sets request param 'authenticated' to False

            return self.get_response(request)  #returns authenticated request to views.py in Django (the page's controller function)
