# Synthetic log generator for IBM Cloud Logs

Code Engine go lang application that generates random log data

## Setup

- Provision a Cloud Logs instance
- Create an API key

Creating an API key can be performed using the [IBM Cloud Shell](https://cloud.ibm.com/shell)

```
$ ibmcloud iam api-key-create demo-key -d "Demo API key" --file key_file
$ cat key_file
```

From the IBM Cloud Shell, assuming you generated a key_file we can get the two configuration elements we need. 

Get the API Key (please note: this is a secret and should be managed accordingly)
```
$ jq ".apikey" key_file
```

For the Code Engine application, we will set this value as the environment variable `API_KEY`.

The Cloud Logs endpoint can be found via the [Web UI](https://cloud.ibm.com/observe/logging) or via the command line
```
$ ibmcloud resource service-instances --service-name logs --long --output JSON | jq ".[].extensions.external_ingress"
```

For the Code Engine application, we will decorate this domain name with a leading `https://` and append `/logs/v1/singles` - then set the resulting string as the environment variable `ENDPOINT`.

## Code Engine Application deployment

We will visit the [Code Engine landing page](https://cloud.ibm.com/codeengine/overview) - we can leap in and click on the "Let's Go" button to start.

This will take us to the [start page](https://cloud.ibm.com/codeengine/create/start) - the first step we need to take is to "Create project".

Once the project has been created we will begin by chosing to build an application, and we will make the Code selection that we want to "Build container image from source". The code repo will be this repository [https://github.com/andrewlow/log-generator](https://github.com/andrewlow/log-generator).

You will be required to "Specify Build Details" - we can skip through accepting the defaults, but we do need to specify a namespace and image name to make the build valid. It doesn't matter what name you use, but `ce-log-generator` is a good suggestion.

Make sure you define the two environment variables `API_KEY` and `ENDPOINT` that we found values for in the section above.

Code Engine will scale your application to zero instances if you do not increase the Autoscaling from a minimum of zero, then the application will get stopped if there is no web traffic - stopping the generation of log data.

You should be able to click on the "Create" button which will build the application and start it running, this should only take a few minutes.

Once the deploy is done, you can use the "Test Application" button to find a link to the "Application URL" which will let you get a response from the web server we just deployed. This application is also generating synthetic log messages using the `API_KEY` and `ENDPOINT` provided.

You can now visit the Cloud Logs Web UI to see the flow of data.
