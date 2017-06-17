/*
 * Copyright 2010-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
import * as CryptoJS from 'crypto-js';
import {utils} from './utils';
import * as axios from 'axios';

export const sigV4ClientFactory = {
  newClient: function (config: any) {
      var AWS_SHA_256 = 'AWS4-HMAC-SHA256';
      var AWS4_REQUEST = 'aws4_request';
      var AWS4 = 'AWS4';
      var X_AMZ_DATE = 'x-amz-date';
      var X_AMZ_SECURITY_TOKEN = 'x-amz-security-token';
      var HOST = 'host';
      var AUTHORIZATION = 'Authorization';

      function hash(value: any) {
          return CryptoJS.SHA256(value);
      }

      function hexEncode(value: any) {
          return value.toString(CryptoJS.enc.Hex);
      }

      function hmac(secret: any, value: any) {
          return CryptoJS.HmacSHA256(value, secret, {asBytes: true});
      }

      function buildCanonicalRequest(method: any, path: any, queryParams: any, headers: any, payload: any) {
          return method + '\n' +
              buildCanonicalUri(path) + '\n' +
              buildCanonicalQueryString(queryParams) + '\n' +
              buildCanonicalHeaders(headers) + '\n' +
              buildCanonicalSignedHeaders(headers) + '\n' +
              hexEncode(hash(payload));
      }

      function hashCanonicalRequest(request: any) {
          return hexEncode(hash(request));
      }

      function buildCanonicalUri(uri: any) {
          return encodeURI(uri);
      }

      function buildCanonicalQueryString(queryParams: any) {
          if (Object.keys(queryParams).length < 1) {
              return '';
          }

          var sortedQueryParams = [];
          for (var property in queryParams) {
              if (queryParams.hasOwnProperty(property)) {
                  sortedQueryParams.push(property);
              }
          }
          sortedQueryParams.sort();

          var canonicalQueryString = '';
          for (var i = 0; i < sortedQueryParams.length; i++) {
              canonicalQueryString += sortedQueryParams[i] + '=' + fixedEncodeURIComponent(queryParams[sortedQueryParams[i]]) + '&';
          }
          return canonicalQueryString.substr(0, canonicalQueryString.length - 1);
      }

      function fixedEncodeURIComponent (str: any) {
        return encodeURIComponent(str).replace(/[!'()*]/g, function(c: any) {
          return '%' + c.charCodeAt(0).toString(16);
        });
      }

      function buildCanonicalHeaders(headers: any) {
          var canonicalHeaders = '';
          var sortedKeys = [];
          for (var property in headers) {
              if (headers.hasOwnProperty(property)) {
                  sortedKeys.push(property);
              }
          }
          sortedKeys.sort();

          for (var i = 0; i < sortedKeys.length; i++) {
              canonicalHeaders += sortedKeys[i].toLowerCase() + ':' + headers[sortedKeys[i]] + '\n';
          }
          return canonicalHeaders;
      }

      function buildCanonicalSignedHeaders(headers: any) {
          var sortedKeys = [];
          for (var property in headers) {
              if (headers.hasOwnProperty(property)) {
                  sortedKeys.push(property.toLowerCase());
              }
          }
          sortedKeys.sort();

          return sortedKeys.join(';');
      }

      function buildStringToSign(datetime: any, credentialScope: any, hashedCanonicalRequest: any) {
          return AWS_SHA_256 + '\n' +
              datetime + '\n' +
              credentialScope + '\n' +
              hashedCanonicalRequest;
      }

      function buildCredentialScope(datetime: any, region: any, service: any) {
          return datetime.substr(0, 8) + '/' + region + '/' + service + '/' + AWS4_REQUEST;
      }

      function calculateSigningKey(secretKey: any, datetime: any, region: any, service: any) {
          return hmac(hmac(hmac(hmac(AWS4 + secretKey, datetime.substr(0, 8)), region), service), AWS4_REQUEST);
      }

      function calculateSignature(key: any, stringToSign: any) {
          return hexEncode(hmac(key, stringToSign));
      }

      function buildAuthorizationHeader(accessKey: any, credentialScope: any, headers: any, signature: any) {
          return AWS_SHA_256 + ' Credential=' + accessKey + '/' + credentialScope + ', SignedHeaders=' + buildCanonicalSignedHeaders(headers) + ', Signature=' + signature;
      }

      // if(config.accessKey === undefined || config.secretKey === undefined) {
      //     return {};
      // }

      var awsSigV4Client = {
        accessKey: utils.assertDefined(config.accessKey, 'accessKey'),
        secretKey: utils.assertDefined(config.secretKey, 'secretKey'),
        sessionToken: config.sessionToken,
        serviceName: utils.assertDefined(config.serviceName, 'serviceName'),
        region: utils.assertDefined(config.region, 'region'),
        endpoint: utils.assertDefined(config.endpoint, 'endpoint'),
        makeRequest: function (request: any) {
            var verb = utils.assertDefined(request.verb, 'verb');
            var path = utils.assertDefined(request.path, 'path');
            var queryParams = utils.copy(request.queryParams);
            if (queryParams === undefined) {
                queryParams = {};
            }
            var headers = utils.copy(request.headers);
            if (headers === undefined) {
                headers = {};
            }

            // if the user has not specified an override for Content type the use default
            if (headers['Content-Type'] === undefined) {
                headers['Content-Type'] = config.defaultContentType;
            }

            // if the user has not specified an override for Accept type the use default
            if (headers['Accept'] === undefined) {
                headers['Accept'] = config.defaultAcceptType;
            }

            var body = utils.copy(request.body);
            if (body === undefined || verb === 'GET') { // override request body and set to empty when signing GET requests
                body = '';
            }  else {
                body = JSON.stringify(body);
            }

            // if there is no body remove the content-type header so it is not included in SigV4 calculation
            if (body === '' || body === undefined || body === null) {
                delete headers['Content-Type'];
            }

            var datetime = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z').replace(/[:\-]|\.\d{3}/g, '');
            headers[X_AMZ_DATE] = datetime;
            var parser = document.createElement('a');
            parser.href = this.endpoint;
            headers[HOST] = parser.hostname;

            var canonicalRequest = buildCanonicalRequest(verb, path, queryParams, headers, body);
            var hashedCanonicalRequest = hashCanonicalRequest(canonicalRequest);
            var credentialScope = buildCredentialScope(datetime, this.region, this.serviceName);
            var stringToSign = buildStringToSign(datetime, credentialScope, hashedCanonicalRequest);
            var signingKey = calculateSigningKey(this.secretKey, datetime, this.region, this.serviceName);
            var signature = calculateSignature(signingKey, stringToSign);
            headers[AUTHORIZATION] = buildAuthorizationHeader(this.accessKey, credentialScope, headers, signature);
            if (this.sessionToken !== undefined && this.sessionToken !== '') {
                headers[X_AMZ_SECURITY_TOKEN] = this.sessionToken;
            }
            delete headers[HOST];

            var url = config.endpoint + path;
            var queryString = buildCanonicalQueryString(queryParams);
            if (queryString !== '') {
                url += '?' + queryString;
            }

            // need to re-attach Content-Type if it is not specified at this point
            if (headers['Content-Type'] === undefined) {
                headers['Content-Type'] = config.defaultContentType;
            }

            var signedRequest = {
                method: verb,
                url: url,
                headers: headers,
                data: body,
                validateStatus: function (status: number) {
                  return status >= 200 && status < 500; // 300 default
                }
            };
            return axios.default(signedRequest);
        }
      };

      return awsSigV4Client;
  }
};
