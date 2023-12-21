'use strict';

const when = require('when');
const {get} = require('@node-ntlm/httpreq')
const _ = require('lodash');

const fs = require('fs');

const NtlmSecurity = require('./ntlm/ntlmSecurity');
const HttpClient = require('./ntlm/http');

// define ntlm auth
const NTLMAuth = function(config, options) {
  if (!options) {
    options = {};
  }
  const passwordIsPlainText = _.has(config, 'password');
  const passwordIsEncrypted = _.has(config, 'nt_password') && _.has(config, 'lm_password');

  if(typeof config === 'object'
    && _.has(config, 'host')
    && _.has(config, 'username')
    && (passwordIsPlainText || passwordIsEncrypted)
  ) {
    return {
      wsdlOptions: { httpClient: HttpClient },
      authProfile: new NtlmSecurity(config, options),
      getUrl: function(url, filePath) {
        let ntlmOptions = { 'username': config.username };
        if (passwordIsPlainText) {
          ntlmOptions.password = config.password;
        }
        else {
          ntlmOptions.nt_password = config.nt_password;
          ntlmOptions.lm_password = config.lm_password;
        }
        ntlmOptions = _.merge(ntlmOptions, _.clone(options));
        ntlmOptions.url = url;
        return when.promise((resolve, reject) => {
          get({
            url: ntlmOptions.url,
            username: config.username,
            password: config.password,
            domain: config.domain ?? '',
            worksstation: config.worksstation ?? '',
          })
            .then(
              (res) => {
                fs.writeFile(filePath, res.body, (err) => {
                  if(err) reject(err);
                  else resolve(filePath);
                });
              },
              (err) => {
                reject(err);
              }
            )
        });
      }
    };
  } else {
    throw new Error('missing required config parameters');
  }
};

module.exports = NTLMAuth;