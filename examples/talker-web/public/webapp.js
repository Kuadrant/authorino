const handleResponse = response => {
  if (response.ok) {
    return response
  }

  var message = `${response.status} ${response.statusText}`

  for (var header of response.headers.entries()) {
    if (header[0] === 'x-ext-auth-reason') {
      message += ` (reason: ${header[1]})`
    }
  }

  throw new Error(message)
}

const renderResponse = (resp) => {
  document.getElementById('response').innerHTML = resp
}

const send = (e) => {
  e.preventDefault()
  data = e.target.dataset
  fetch(data.path, { method: data.method })
    .then(response => handleResponse(response).json())
    .then(data => renderResponse(JSON.stringify(data, null, 2)))
    .catch(err => renderResponse(err.message))
}

const operations = [
  { method: 'GET', endpoint: '/hello' },
  { method: 'GET', endpoint: '/greetings' },
  { method: 'POST', endpoint: '/greetings' },
  { method: 'GET', endpoint: '/greetings/1' },
  { method: 'PUT', endpoint: '/greetings/1' },
  { method: 'DELETE', endpoint: '/greetings/1' },
  { method: 'GET', endpoint: '/greetings/2' },
  { method: 'PUT', endpoint: '/greetings/2' },
  { method: 'DELETE', endpoint: '/greetings/2' },
  { method: 'GET', endpoint: '/goodbye' },
]

operations.forEach(operation => {
  const method = operation.method
  const endpoint = operation.endpoint

  a = document.createElement('a')
  a.setAttribute('data-method', method)
  a.setAttribute('data-path', endpoint)
  a.setAttribute('href', endpoint)
  a.innerHTML = `${method} ${endpoint}`
  a.onclick = send
  li = document.createElement('li')
  li.classList.add('link')
  li.append(a)
  document.getElementById('menu').append(li)
})
