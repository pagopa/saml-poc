
import http from 'k6/http';
import { check } from 'k6';

const TOTAL_MAXIMUM_RPS = 50;
const TOTAL_MINIMUM_RPS = 10;

function rate(ref, percentage) {
  return ref * percentage;
}

export const options = {
  discardResponseBodies: true,
  scenarios: {
    ramping_up_login: {
      executor: 'ramping-arrival-rate',

      exec: 'saml_login',

      // Start iterations per `timeUnit`
      startRate: rate(TOTAL_MINIMUM_RPS,0.5),

      // Start `startRate` iterations per seconds
      timeUnit: '1s',

      // Pre-allocate necessary VUs.
      preAllocatedVUs: 100,

      // max allowed vu
      maxVUs: 200,

      stages: [
        // Start 50 iterations per `timeUnit` for the first minute.
        { target: rate(TOTAL_MINIMUM_RPS + 10,0.5), duration: '1m' },

        // // Linearly ramp-up to starting 100 iterations per `timeUnit` over the following two minutes.
        { target: rate(TOTAL_MINIMUM_RPS + 20,0.5), duration: '1m' },

        // // Continue starting 300 iterations per `timeUnit` for the following two minutes.
        { target: rate(TOTAL_MAXIMUM_RPS,0.5), duration: '2m' }
      ],
    },
    ramping_up_acs: {
        executor: 'ramping-arrival-rate',

        exec: 'saml_acs',
  
        startRate: rate(TOTAL_MINIMUM_RPS,0.5),

        // Start `startRate` iterations per seconds
        timeUnit: '1s',
  
        // Pre-allocate necessary VUs.
        preAllocatedVUs: 100,
  
        // max allowed vu
        maxVUs: 200,
  
        stages: [
          // Start 50 iterations per `timeUnit` for the first minute.
          { target: rate(TOTAL_MINIMUM_RPS + 10,0.5), duration: '1m' },
  
          // // Linearly ramp-up to starting 100 iterations per `timeUnit` over the following two minutes.
          { target: rate(TOTAL_MINIMUM_RPS + 20,0.5), duration: '1m' },
  
          // // Continue starting 300 iterations per `timeUnit` for the following two minutes.
          { target: rate(TOTAL_MAXIMUM_RPS,0.5), duration: '2m' }
        ],
      },
    constant_login: {
      executor: 'constant-arrival-rate',

      exec: 'saml_login',

      // test duration
      duration: '4m',

      // test rate
      rate: rate(TOTAL_MAXIMUM_RPS,0.5),

      // It should start `rate` iterations per second
      timeUnit: '1s',

      // pre-allocate vu
      preAllocatedVUs: 200,

      // max allowed vu
      maxVUs: 300,

      // start time calculated on ramping scenarios termination time
      startTime: '4m',

    },
    constant_acs: {
        executor: 'constant-arrival-rate',

        exec: 'saml_acs',

        // test duration
        duration: '4m',
  
        // test rate
        rate: rate(TOTAL_MAXIMUM_RPS,0.5),
  
        // It should start `rate` iterations per second
        timeUnit: '1s',
  
        // pre-allocate vu
        preAllocatedVUs: 200,
  
        // max allowed vu
        maxVUs: 300,
  
        // start time calculated on ramping scenarios termination time
        startTime: '4m',
  
      },
    ramping_down_login: {
      executor: 'ramping-arrival-rate',

      exec: 'saml_login',


      // Start iterations per `timeUnit`
      startRate: rate(TOTAL_MAXIMUM_RPS,0.5),

      // Start `startRate` iterations per seconds
      timeUnit: '1s',

      // Pre-allocate necessary VUs.
      preAllocatedVUs: 200,

      // max allowed vu
      maxVUs: 300,
      
      startTime: '8m',

      stages: [
        // Start 300 iterations per `timeUnit` for four minutes.
        { target: rate(TOTAL_MAXIMUM_RPS - 20,0.5), duration: '1m' },

        // Linearly ramp-down to starting 100 iterations per `timeUnit` over the following two minutes.
        { target: rate(TOTAL_MAXIMUM_RPS - 30,0.5), duration: '1m' },

        // Continue starting 50 iterations per `timeUnit` for the following minute.
        { target: rate(TOTAL_MINIMUM_RPS,0.5), duration: '2m' }
      ],
    },
    ramping_down_acs: {
        executor: 'ramping-arrival-rate',

        exec: 'saml_acs',

  
        // Start iterations per `timeUnit`
        startRate: rate(TOTAL_MAXIMUM_RPS,0.5),

        // Start `startRate` iterations per seconds
        timeUnit: '1s',
  
        // Pre-allocate necessary VUs.
        preAllocatedVUs: 200,
  
        // max allowed vu
        maxVUs: 300,
        
        startTime: '8m',
  
        stages: [
          // Start 300 iterations per `timeUnit` for four minutes.
          { target: rate(TOTAL_MAXIMUM_RPS - 20,0.5), duration: '1m' },
  
          // Linearly ramp-down to starting 100 iterations per `timeUnit` over the following two minutes.
          { target: rate(TOTAL_MAXIMUM_RPS - 30,0.5), duration: '1m' },
  
          // Continue starting 50 iterations per `timeUnit` for the following minute.
          { target: rate(TOTAL_MINIMUM_RPS,0.5), duration: '2m' }
        ],
      },
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

export function saml_acs() {
  var url_response = `https://dev.oneidentity.pagopa.it/saml/acs`;
  var body = {
    RelayState: 'ZA17oBcK8dj2n8AwK-FSrJu8EBcXGK0im_Z6VlSd8EEtj3Do7a0ly3Ln',
    SAMLResponse: 'PHNhbWxwOlJlc3BvbnNlIERlc3RpbmF0aW9uPSJodHRwczovL2Rldi5vbmVpZGVudGl0eS5wYWdvcGEuaXQvc2FtbC9hY3MiIElEPSJfMmYxZWFjNzEtMWQ5MS00MmMxLTkzYWEtNzkzNGRhOTg0N2RiIiBJblJlc3BvbnNlVG89ImlkLWYxNTU0ZjZiNzZlM2NiYzU3YWEwZmFhOWRjMDUyMmIwMTJlOWQ3MGUiIElzc3VlSW5zdGFudD0iMjAyNC0wMy0yN1QxMzo0NTozMloiIFZlcnNpb249IjIuMCIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCI+DQogICAgPHNhbWw6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5odHRwczovL2RlbW8uc3BpZC5nb3YuaXQ8L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48ZHM6UmVmZXJlbmNlIFVSST0iI18yZjFlYWM3MS0xZDkxLTQyYzEtOTNhYS03OTM0ZGE5ODQ3ZGIiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT51NHBZbXNXVG11UjUvRjFtc1NkL05zMlc0Q3pGSVR5VXVxL0lrMmpNM0tVPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5HL1pHTmlidEdrRWJOc0pqYUhKemJySGkrbmc2ZG9EN0ZyNnF2dVgwUS96REViRGFZZXlRSkVONmYxRGMvdCt0VWV5NzF3U012WGhBa1FMck9WUGROZ05DbjRrVXp4QnVWdnUvRmVEdUY3UG9CTk5LTzc0MnZzTURWd1NpTU5KbVJHWG9YdFZqWjVFczdUengyR0JqL1lvQVpuaHFLcnJpbzZrSTFtZ2lyUGJjSXE4cE15dFFKVWd2UWdNZVI3eHlXZ0Z5aVZwSkt5S1J0c1JkNDVIMityMEFQUk1xYjlmaWtON0toVHk5dEwxdXF4VHpsbENpb0Q0VzJYaEJodlgwNG9KeFVHV0lsZExIUU94aGJHS2xuQmJBbmZaajE4aitUaTVKd1BvaXpXTUE0VnRoQ252TlpENVF3VDQ3SEJVaTdBVFZ6bGgzais5bHNmN3lrWi9LRFE9PTwvZHM6U2lnbmF0dXJlVmFsdWU+PGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRUdEQ0NBd0NnQXdJQkFnSUpBT3JZajlvTEVKQ3dNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1HVXhDekFKQmdOVkJBWVRBa2xVTVE0d0RBWURWUVFJRXdWSmRHRnNlVEVOTUFzR0ExVUVCeE1FVW05dFpURU5NQXNHQTFVRUNoTUVRV2RKUkRFU01CQUdBMVVFQ3hNSlFXZEpSQ0JVUlZOVU1SUXdFZ1lEVlFRREV3dGhaMmxrTG1kdmRpNXBkREFlRncweE9UQTBNVEV4TURBeU1EaGFGdzB5TlRBek1EZ3hNREF5TURoYU1HVXhDekFKQmdOVkJBWVRBa2xVTVE0d0RBWURWUVFJRXdWSmRHRnNlVEVOTUFzR0ExVUVCeE1FVW05dFpURU5NQXNHQTFVRUNoTUVRV2RKUkRFU01CQUdBMVVFQ3hNSlFXZEpSQ0JVUlZOVU1SUXdFZ1lEVlFRREV3dGhaMmxrTG1kdmRpNXBkRENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFLOGtKVm8rdWdScmJidjl4aFhDdVZycWk0QjcvTVF6UWM2Mm9jd2xGRnVqSk5kNG0xbVhrVUhGYmd2d2hSa1FxbzJEQW1GZUhpd0NrSlQzSzFlZVhJRmhORkZyb0V6R1B6T055ZWtMcGpOdm1ZSXMxQ0Z2aXJHT2owYmtFaUdhS0VzKy91bXpHanhJaHk1SlFscVhFOTZ5MStJenAyUWhKaW1ESzAvS05pajhJMWJ6eHNlUDBZZ2M0U0Z2ZUtTKzdRTytQckx6V2tsRVdHTXM0RE01WmMzVlJLN2c0TFdQV1poS2RJbUMxcm5TKy9sRW1IU3ZIaXNkVnAvREp0YlNyWndTWVRSdlRUejVJWkRTcTRrQXpyRGZwajE2aDdiM3QzbkZHYzhVb1kyUm80dFJaM2FoSjJyM2I3OXlLNkM1cGhZN0NBQU51VzNnRGRoVmppQk5ZczBDQXdFQUFhT0J5akNCeHpBZEJnTlZIUTRFRmdRVTMvN2tWMnRiZEZ0cGhiU0E0TEg3K3c4U2tjd3dnWmNHQTFVZEl3U0JqekNCaklBVTMvN2tWMnRiZEZ0cGhiU0E0TEg3K3c4U2tjeWhhYVJuTUdVeEN6QUpCZ05WQkFZVEFrbFVNUTR3REFZRFZRUUlFd1ZKZEdGc2VURU5NQXNHQTFVRUJ4TUVVbTl0WlRFTk1Bc0dBMVVFQ2hNRVFXZEpSREVTTUJBR0ExVUVDeE1KUVdkSlJDQlVSVk5VTVJRd0VnWURWUVFERXd0aFoybGtMbWR2ZGk1cGRJSUpBT3JZajlvTEVKQ3dNQXdHQTFVZEV3UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFKTkZxWGcvVjNhaW1KS1VtVWFxbVFFRW9TYzNxdlhGSVR2VDVmNWJLdzl5ay9OVmhSNnduZEwrei8yNGgxT2RScXM3NmJsZ0g4azExNnFXTmtrRHR0MEFsU2pRT3g1cXZGWWgxVXZpT2pOZFJJNFdrWU9OU3crdnVhdmN4K2ZCNk81SkRITm1NaE15U0tUbm1ScVRreWhqcmNoN3phRklXVVNWN2hzQnV4cHFtcldEb0xXZFhiVjNlRkgzbUlOQTVBb0lZL20wYlp0elo3WU5naUZXenhRZ2VrcHhkMHZjVHNlTW5DY1huc0FsY3RkaXIwRm9DWnp0eE11WmpsQmp3TFR0TTZSeTMvNDhMTU04WitsdzdOTWNpS0xMVEdReVU4WG1LS1NTT2gwZEdoNUxybHQ1R3hJSUprSDgxQzBZaW1XZWJ6ODQ2NFFQTDNSYkxuVEtnK2M9PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+DQoNCiAgICA8c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz4NCiAgICA8c2FtbDpBc3NlcnRpb24gSUQ9Il84MjQyZjAwMC1kNGMyLTQyYWYtODg4ZS1hNzgyMGUzMTYxNjAiIElzc3VlSW5zdGFudD0iMjAyNC0wMy0yN1QxMzo0NTozMloiIFZlcnNpb249IjIuMCIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIj4NCiAgICAgICAgPHNhbWw6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5odHRwczovL2RlbW8uc3BpZC5nb3YuaXQ8L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48ZHM6UmVmZXJlbmNlIFVSST0iI184MjQyZjAwMC1kNGMyLTQyYWYtODg4ZS1hNzgyMGUzMTYxNjAiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT5hWDNrN2ViS2poRUFsc0R1VXdjWnA5QnN2bjdEUkMrVlVraTZDZytiNGgwPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5TbTBrOHpHcHdWeWNqdnoxbHovOEZaVjV5TzJJb08zNFpJd1hjbUpkQXF4MEI3MjNWQmJkTFZvYnNjLzdld2hFd2dpeTZNVmpzVFBSeU8rVGJSZVVwdHl4SmRUU0pJWHdWTnNHTERDb2hkMHhGN0loeGtaOSs4OEwwbHI0bFgyQ1F2WEEyL3Z4SWowNmErSyswa1VqbGFHNzFpM0VPSlErWjMwSWRNNytYdTlJL0Q2TnhHckorODBIa1c3T2Fsek12eEY2QTEwTlp4MldPZm9SSEVubC9CQVV2Ymk1amdnTnNUL3QrcGdrU29tR1dOQnJNbEpxSjJZcDBQR3REbUVkbjJtR0dOeHZyTW1zaDdaNVlPS0d5dFYvTmVNMENiZXIveUpRVzZpeTg5U3FqK2EwVnJaUmpWM05Cb0xPQ05wTkhlR2g4eWtuNCs2YUZzL29NTzhoM3c9PTwvZHM6U2lnbmF0dXJlVmFsdWU+PGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRUdEQ0NBd0NnQXdJQkFnSUpBT3JZajlvTEVKQ3dNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1HVXhDekFKQmdOVkJBWVRBa2xVTVE0d0RBWURWUVFJRXdWSmRHRnNlVEVOTUFzR0ExVUVCeE1FVW05dFpURU5NQXNHQTFVRUNoTUVRV2RKUkRFU01CQUdBMVVFQ3hNSlFXZEpSQ0JVUlZOVU1SUXdFZ1lEVlFRREV3dGhaMmxrTG1kdmRpNXBkREFlRncweE9UQTBNVEV4TURBeU1EaGFGdzB5TlRBek1EZ3hNREF5TURoYU1HVXhDekFKQmdOVkJBWVRBa2xVTVE0d0RBWURWUVFJRXdWSmRHRnNlVEVOTUFzR0ExVUVCeE1FVW05dFpURU5NQXNHQTFVRUNoTUVRV2RKUkRFU01CQUdBMVVFQ3hNSlFXZEpSQ0JVUlZOVU1SUXdFZ1lEVlFRREV3dGhaMmxrTG1kdmRpNXBkRENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFLOGtKVm8rdWdScmJidjl4aFhDdVZycWk0QjcvTVF6UWM2Mm9jd2xGRnVqSk5kNG0xbVhrVUhGYmd2d2hSa1FxbzJEQW1GZUhpd0NrSlQzSzFlZVhJRmhORkZyb0V6R1B6T055ZWtMcGpOdm1ZSXMxQ0Z2aXJHT2owYmtFaUdhS0VzKy91bXpHanhJaHk1SlFscVhFOTZ5MStJenAyUWhKaW1ESzAvS05pajhJMWJ6eHNlUDBZZ2M0U0Z2ZUtTKzdRTytQckx6V2tsRVdHTXM0RE01WmMzVlJLN2c0TFdQV1poS2RJbUMxcm5TKy9sRW1IU3ZIaXNkVnAvREp0YlNyWndTWVRSdlRUejVJWkRTcTRrQXpyRGZwajE2aDdiM3QzbkZHYzhVb1kyUm80dFJaM2FoSjJyM2I3OXlLNkM1cGhZN0NBQU51VzNnRGRoVmppQk5ZczBDQXdFQUFhT0J5akNCeHpBZEJnTlZIUTRFRmdRVTMvN2tWMnRiZEZ0cGhiU0E0TEg3K3c4U2tjd3dnWmNHQTFVZEl3U0JqekNCaklBVTMvN2tWMnRiZEZ0cGhiU0E0TEg3K3c4U2tjeWhhYVJuTUdVeEN6QUpCZ05WQkFZVEFrbFVNUTR3REFZRFZRUUlFd1ZKZEdGc2VURU5NQXNHQTFVRUJ4TUVVbTl0WlRFTk1Bc0dBMVVFQ2hNRVFXZEpSREVTTUJBR0ExVUVDeE1KUVdkSlJDQlVSVk5VTVJRd0VnWURWUVFERXd0aFoybGtMbWR2ZGk1cGRJSUpBT3JZajlvTEVKQ3dNQXdHQTFVZEV3UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFKTkZxWGcvVjNhaW1KS1VtVWFxbVFFRW9TYzNxdlhGSVR2VDVmNWJLdzl5ay9OVmhSNnduZEwrei8yNGgxT2RScXM3NmJsZ0g4azExNnFXTmtrRHR0MEFsU2pRT3g1cXZGWWgxVXZpT2pOZFJJNFdrWU9OU3crdnVhdmN4K2ZCNk81SkRITm1NaE15U0tUbm1ScVRreWhqcmNoN3phRklXVVNWN2hzQnV4cHFtcldEb0xXZFhiVjNlRkgzbUlOQTVBb0lZL20wYlp0elo3WU5naUZXenhRZ2VrcHhkMHZjVHNlTW5DY1huc0FsY3RkaXIwRm9DWnp0eE11WmpsQmp3TFR0TTZSeTMvNDhMTU04WitsdzdOTWNpS0xMVEdReVU4WG1LS1NTT2gwZEdoNUxybHQ1R3hJSUprSDgxQzBZaW1XZWJ6ODQ2NFFQTDNSYkxuVEtnK2M9PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+DQogICAgICAgIDxzYW1sOlN1YmplY3Q+DQogICAgICAgICAgICA8c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDp0cmFuc2llbnQiIE5hbWVRdWFsaWZpZXI9Imh0dHBzOi8vZGVtby5zcGlkLmdvdi5pdCI+DQogICAgICAgICAgICAgICAgICAgIF9mNTc3NjA1MS1kYTkyLTRjYjktOGUzNC1hYmM0Y2NiODk0ZjQNCiAgICAgICAgICAgIDwvc2FtbDpOYW1lSUQ+DQogICAgICAgICAgICA8c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+DQogICAgICAgICAgICAgICAgPHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgSW5SZXNwb25zZVRvPSJpZC1mMTU1NGY2Yjc2ZTNjYmM1N2FhMGZhYTlkYzA1MjJiMDEyZTlkNzBlIiBOb3RPbk9yQWZ0ZXI9IjIwMjQtMDMtMjdUMTM6NTA6MDhaIiBSZWNpcGllbnQ9Imh0dHBzOi8vZGV2Lm9uZWlkZW50aXR5LnBhZ29wYS5pdC9zYW1sL2FjcyIvPg0KICAgICAgICAgICAgPC9zYW1sOlN1YmplY3RDb25maXJtYXRpb24+DQogICAgICAgIDwvc2FtbDpTdWJqZWN0Pg0KICAgICAgICA8c2FtbDpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAyNC0wMy0yN1QxMzo0NTozMloiIE5vdE9uT3JBZnRlcj0iMjAyNC0wMy0yN1QxMzo1MDowOFoiPg0KICAgICAgICAgICAgPHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj4NCiAgICAgICAgICAgICAgICA8c2FtbDpBdWRpZW5jZT5odHRwczovL2Rldi5vbmVpZGVudGl0eS5wYWdvcGEuaXQvc2FtbC9tZXRhZGF0YTwvc2FtbDpBdWRpZW5jZT4NCiAgICAgICAgICAgIDwvc2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPg0KICAgICAgICA8L3NhbWw6Q29uZGl0aW9ucz4gDQogICAgICAgIDxzYW1sOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAyNC0wMy0yN1QxMzo0NTozMloiIFNlc3Npb25JbmRleD0iXzQzOTQzZjJhLTViM2ItNGVlOS1iMDUxLTEyMGYzMWQ3NTgxMCI+DQogICAgICAgICAgICA8c2FtbDpBdXRobkNvbnRleHQ+DQogICAgICAgICAgICAgICAgPHNhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+aHR0cHM6Ly93d3cuc3BpZC5nb3YuaXQvU3BpZEwyPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPg0KICAgICAgICAgICAgPC9zYW1sOkF1dGhuQ29udGV4dD4NCiAgICAgICAgPC9zYW1sOkF1dGhuU3RhdGVtZW50Pg0KICAgICAgICA8c2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJmaXNjYWxOdW1iZXIiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5USU5JVC1GTFBDUFQ2OUE2NVozMzZQPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L3NhbWw6QXR0cmlidXRlPiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8c2FtbDpBdHRyaWJ1dGUgTmFtZT0ibmFtZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPkNsZW9wYXRyYSBUZWE8L3NhbWw6QXR0cmlidXRlVmFsdWU+ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvc2FtbDpBdHRyaWJ1dGU+ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJmYW1pbHlOYW1lIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+Rmlsb3BhdG9yZTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9zYW1sOkF0dHJpYnV0ZT4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPHNhbWw6QXR0cmlidXRlIE5hbWU9ImRhdGVPZkJpcnRoIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOmRhdGUiPjE5NjktMDEtMjU8L3NhbWw6QXR0cmlidXRlVmFsdWU+ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvc2FtbDpBdHRyaWJ1dGU+ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9zYW1sOkF0dHJpYnV0ZVN0YXRlbWVudD4NCiAgICA8L3NhbWw6QXNzZXJ0aW9uPg0KPC9zYW1scDpSZXNwb25zZT4='
  }
  var r = http.post(url_response, body);
  check(r, {
    'status is 200': (r) => r.status === 200,
  });
  if (r.status != 200) {
    console.log(`Status acs ${r.status}`);
  }
}

export function saml_login(){
  var url_request = `https://dev.oneidentity.pagopa.it/hello`;
  var r = http.get(url_request);
  check(r, {
    'status is 200': (r) => r.status === 200,
  });
  if (r.status != 200) {
    console.log(`Status login ${r.status}`);
  }
}