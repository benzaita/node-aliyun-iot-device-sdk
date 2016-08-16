const Promise = require('bluebird');
const request = Promise.promisifyAll(require('request'), {multiArgs: true});
const mqtt = require('mqtt');
const crypto = require('crypto');

function signature(params, appSecret, deviceSecret) {
  const canonQueryString = Object.keys(params).sort().
    filter(key => key.toLowerCase()!='sign').
    map(key => `${key}${params[key]}`).join('')

  const key = appSecret + deviceSecret
  const hmac = crypto.createHmac('md5', key);
  hmac.update(canonQueryString);
  return hmac.digest('hex').toUpperCase();
}

function createUsername(appKey, appSecret, deviceId, deviceSecret) {
  const data = appKey + appSecret + deviceId + deviceSecret;
  const hash = crypto.createHash('md5');
  hash.update(data);
  return hash.digest('hex').toUpperCase();
}

function verify() {
  throw new Error('not implements');
}

const auth = Promise.coroutine(function*(appKey, appSecret, deviceId, deviceSecret) {
  const aliyun = 'http://manager.channel.aliyun.com/iot/auth';
  const params = {
    deviceName: deviceId,
    productKey: appKey,
    signMethod: 'HmacMD5',
    protocol: 'mqtt'
  }

  params.sign = signature(params, appSecret, deviceSecret);
  const url = aliyun + '?' + Object.keys(params).map(x => `${x}=${params[x]}`).join('&')

  const replies = yield request.getAsync(url);
  const responseData = JSON.parse(replies[1]);
  const pubkey = new Buffer(responseData.pubkey, 'base64');
  const serverInfo = responseData.servers.split(':');
  const host = serverInfo[0];
  const port = serverInfo[1].split('|');
  const deviceIdFromAuth = responseData.deviceId

  return {pubkey, host, port, deviceId: deviceIdFromAuth};
});

const connect = Promise.coroutine(function*(appKey, appSecret, deviceId, deviceSecret) {

  const authResult = yield auth(appKey, appSecret, deviceId, deviceSecret);
  const pubkey = authResult.pubkey;
  const host = authResult.host;
  const port = authResult.port;
  const deviceIdFromAuth = authResult.deviceId;

  console.log(pubkey.toString());

  const params = {
    clientId: appKey + ':' + deviceIdFromAuth,
    username: createUsername(appKey, appSecret, deviceIdFromAuth, deviceSecret),
    rejectUnauthorized: false,
    cert: pubkey,
    keepalive: 65
  }

  console.log(params)
  return mqtt.connect(`ssl://${host}:${port[0]}`, params);

});

module.exports = connect;
