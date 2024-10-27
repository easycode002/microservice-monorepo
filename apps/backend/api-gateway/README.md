# API Proxy

### Improve api-proxy

<details>

##### Define the CORS options.
```sh
import configs from "@/src/config";

const corsOptions = {
  origin: configs.clientUrl,
  credentials: true, // Request includes credentials like cookies
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'],
};

console.log('corsOption:::', corsOptions)

export default corsOptions;
```

##### Define route paths and configuration.
```sh
import configs from "@/src/config"

export interface RouteConfig {
  path: string;
  target?: string;
  methods?: {
    [method: string]: {
      authRequired: boolean;
      roles?: string[]; // Optional: Roles that are allowed
    };
  };
  nestedRoutes?: RouteConfig[];
}

export interface RoutesConfig {
  [route: string]: RouteConfig;
}

const ROUTE_PATHS: RoutesConfig = {
  AUTH_SERVICE: {
    path: "/v1/auth",
    target: configs.authServiceUrl,
    nestedRoutes: [
      {
        path: "/health",
        methods: {
          GET: {
            authRequired: false,
          }
        },
      },
      {
        path: "/signup",
        methods: {
          POST: {
            authRequired: false,
          }
        },
      },
      {
        path: "/signin",
        methods: {
          POST: {
            authRequired: false,
          }
        }
      },
      {
        path: "/verify",
        methods: {
          POST: {
            authRequired: false,
          }
        }
      },
      {
        path: '/login',
        methods: {
          POST: {
            authRequired: false,
          }
        }
      },
      {
        path: '/google',
        methods: {
          GET: {
            authRequired: false,
          }
        }
      },
      {
        path: '/facebook',
        methods: {
          GET: {
            authRequired: false,
          }
        }
      },
      {
        path: '/refresh-token',
        methods: {
          POST: {
            authRequired: false,
          }
        }
      },
      {
        path: '/oauth/callback',
        methods: {
          GET: {
            authRequired: false,
          }
        }
      },
    ]
  }
}

export default ROUTE_PATHS
```

##### Define logging functions.
  - Create a file in root `api-gateway`
```sh
# apps/backend/api-gateway/.npmrc
@easycode002:registry=https://npm.pkg.github.com/
//npm.pkg.github.com/:_authToken=<_your_accesToken>

```
  - Install package
```sh
yarn add @easycode002/ms-libss@0.0.1 winston
yarn add @aws-sdk/client-cloudwatch-logs
```
  - Create a file `src/utils/logger.ts`
```sh
import { prettyObject } from '@easycode002/ms-libss';
import { Request, Response } from 'express';
import winston from 'winston';


export const logRequest = (logger: winston.Logger, req: Request, additionalInfo: object = {}) => {
    logger.info(`Incomming Request ${prettyObject({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: req.body,
      ...additionalInfo,
    })}`)
  }
  
  export const logResponse = (logger: winston.Logger, res: Response, additionalInfo: object = {}) => {
    logger.info('Outgoing Response', {
      statusCode: res.statusCode,
      headers: res.getHeaders(),
      ...additionalInfo
    });
  };
```


##### Define proxy configurations for each service
  - Install `http-proxy-middleware`
```sh
yarn add --dev @types/http-proxy-middleware winston-cloudwatch
```
  - Create a file `src/server.ts`
```sh
import configs from "@/src/config";

import app from "@/src/app"
import createLogger from "@/src/utils/logger";

export const gatewayLogger = createLogger({ service: 'api-gateway', level: 'info', logGroupName: configs.awsCloudwatchLogsGroupName });

async function run() {
  try {
    app.listen(configs.port, () => {
      console.log(`Gateway Service running on Port:`, configs.port)
    })
  } catch (error) {
    console.error("Failed to start the application:", error);
    process.exit(1);
  }
}

run();
```
  - Create a file inside `src/middlewares/proxy.ts`
```sh

```

</details>




