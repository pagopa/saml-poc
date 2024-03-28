
import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

export const options = {
  discardResponseBodies: true,
  scenarios: {
    /*ramping_up: {
      executor: 'ramping-arrival-rate',

      // Start iterations per `timeUnit`
      startRate: 10,

      // Start `startRate` iterations per seconds
      timeUnit: '1s',

      // Pre-allocate necessary VUs.
      preAllocatedVUs: 100,

      // max allowed vu
      maxVUs: 200,

      stages: [
        // Start 50 iterations per `timeUnit` for the first minute.
        { target: 20, duration: '1m' },

        // // Linearly ramp-up to starting 100 iterations per `timeUnit` over the following two minutes.
        { target: 30, duration: '1m' },

        // // Continue starting 300 iterations per `timeUnit` for the following two minutes.
        { target: 50, duration: '2m' }
      ],
    },*/
    constant: {
      executor: 'constant-arrival-rate',

      // test duration
      duration: '2m',

      // test rate
      rate: 50,

      // It should start `rate` iterations per second
      timeUnit: '1s',

      // pre-allocate vu
      preAllocatedVUs: 200,

      // max allowed vu
      maxVUs: 300,

      // start time calculated on ramping scenarios termination time
      //startTime: '4m',

    }
    /*ramping_down: {
      executor: 'ramping-arrival-rate',

      // Start iterations per `timeUnit`
      startRate: 50,

      // Start `startRate` iterations per seconds
      timeUnit: '1s',

      // Pre-allocate necessary VUs.
      preAllocatedVUs: 200,

      // max allowed vu
      maxVUs: 300,
      
      startTime: '8m',

      stages: [
        // Start 300 iterations per `timeUnit` for four minutes.
        { target: 30, duration: '1m' },

        // Linearly ramp-down to starting 100 iterations per `timeUnit` over the following two minutes.
        { target: 20, duration: '1m' },

        // Continue starting 50 iterations per `timeUnit` for the following minute.
        { target: 10, duration: '2m' }
      ],
    }*/,
  },
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)', 'count'],
  thresholds: {
    // all thresholds are fulfilled with dummy values 
    // in order to display metrics for each scenario
    http_req_duration: ['max>=0'],
    checks: ['rate>=0'],
}
};

for (let key in options.scenarios) {
  // Each scenario automatically tags the metrics it generates with its own name
  let thresholdHttpReq = `http_req_duration{scenario:${key}}`;
  let thresholdChecks = `checks{scenario:${key}}`;
  // Check to prevent us from overwriting a threshold that already exists
  if (!options.thresholds[thresholdHttpReq]) {
      options.thresholds[thresholdHttpReq] = [];
  }
  if (!options.thresholds[thresholdChecks]) {
    options.thresholds[thresholdChecks] = [];
}
  // uncomment this if you want to override the default threshold
  // options.thresholds[thresholdHttpReq].push('max>=0');
}

//const apiVersion = 'v1';
const throttling = new Counter('throttling');

export default function () {

  //var hostName = `${__ENV.HOST_NAME}`

var url = `https://dev.oneidentity.pagopa.it/saml/metadata`;

var r = http.get(url);

check(r, {
  'status is 200': (r) => r.status === 200,
});

if (r.status === 429) {
  throttling.add(1);
  console.log(`Status ${r.status}`);
}

}