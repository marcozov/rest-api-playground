# Golang REST API + Authentication

The goal of this repository is to implement and use OAUTH2 and OIDC flows in order to get a
better understanding of the topics.

# Authorization Code Flow for browser-based apps

## API
### Build
Building the image.
```
docker build -t marcozoveralli/rest-api-poc ./api
```

### Push
Run
```
docker push marcozoveralli/rest-api-poc
```

### Run
Check the content in `manifests`.

## Frontend
### Build
```
docker build -t marcozoveralli/authorization-frontend-poc ./frontend
```

### Push
Run
```
docker push marcozoveralli/authorization-frontend-poc
```

## Deployment
The API and the frontend are two microservices that are deployed separately.
This repository provides a Kubernetes example.

The folder `manifests` contains the deployment resources for both of them.

The API should not be accessed directly (these attemps will fail due to authentication issues).
The frontend is exposed only within the cluster: it's up to the user to expose it properly.

For testing purpose, port-forward is enough:
```
kubectl port-forward svc/frontend-svc 8080:8080
```

It is then reachable at `localhost:8080` via the browser and it is possible to
trigger the authentication flow by performing the API call via the browser.
