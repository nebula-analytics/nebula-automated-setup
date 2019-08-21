Project Nebula Analytics/Oauth Demo
========

Setup
-----
Ensure you have python 3.7+ installed.

Install required libs:
`pip install -r requirements.txt`.

Obtain a service account id and client secret by following 
the instructions [here](https://developers.google.com/analytics/devguides/reporting/core/v4/authorization).

Add the above information to the empty fields in
 [credentials.json](./credentials.json).

Run
-----
In terminal navigate to the directory of main.py.

To start the server run the command `python main.py`.

In a browser navigate to `https://localhost:5000/oauth/authorize/`
 and complete the oauth flow.
 
You should be redirected to the index page which will now show the following message:
```json
{
  "auth_url": "https://localhost:5000/oauth/authorize/", 
  "host": "https://localhost:5000/", 
  "message": "Hello World", 
  "status": "Online", 
  "upstream": {
    "Google Analytics": "Connected"
  }
}
```

- To test the realtime api navigate to `https://localhost:5000/realtime?ga=<Insert Analytics View ID here>`

- To test the reporting api navigate to `https://localhost:5000/analytics?ga=<Insert Analytics View ID here>`