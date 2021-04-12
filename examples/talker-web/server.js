const express = require('express');
const axios = require('axios')

const clientID = 'webapp'
const clientSecret = 'ca24403c-fd8a-4463-a754-52730c70a823'

const app = express();

app.get('/web/auth/redirect', (req, res) => {
  const requestToken = req.query.code
  console.log(`Requesting token for code ${requestToken}`)

  const params = new URLSearchParams()
  params.append('grant_type', 'authorization_code')
  params.append('code', requestToken)
  params.append('client_id', clientID)
  params.append('client_secret', clientSecret)
  params.append('redirect_uri', 'http://talker-api-authorino.127.0.0.1.nip.io:8000/web/auth/redirect')

  axios.post('http://dex:5556/token', params).then(response => {
    const accessToken = response.data.access_token
    res.cookie('ACCESS-TOKEN', accessToken)
    res.redirect(`/web/index.html`)
  }).catch(error => {
    console.log('Error: ' + error.message)
  })
})

app.use('/web', express.static(__dirname + '/public'))

const server = app.listen(8888, () => {
  console.log("Listening on port %s", server.address().port)
})
