process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const express = require('express');
const fetch = require('node-fetch');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(bodyParser.json());

function handleProxyRequest(req, res, url, method) {
    const headers = {
        'Content-Type': 'application/json',
        'apikey': req.headers['apikey']
    };
    console.log(headers)

    fetch(url, {
        method: method,
        headers: headers,
        body: ['POST', 'PUT'].includes(method) ? JSON.stringify(req.body) : undefined
    })
    .then(response => response.json())
    .then(data => res.json(data))
    .catch(error => res.status(500).json({ error: 'Failed to fetch data' }));
}

app.post('/createOKRTasks', (req, res) => {
    const url = `https://teakresourcescoj8.kanbanize.com/api/v2/cards`;
    handleProxyRequest(req, res, url, 'POST');
});

app.get('/proxy/cards', (req, res) => {
    const url = `https://teakresourcescoj8.kanbanize.com/api/v2/cards`;
    handleProxyRequest(req, res, url, 'GET');
});

app.get('/proxy/cards_desc/:cardID', (req, res) => {
    const cardID = req.params.cardID;
    const url = `https://teakresourcescoj8.kanbanize.com/api/v2/cards/${cardID}`;
    handleProxyRequest(req, res, url, 'GET');
});

app.delete('/proxy/delete_cards/:cardID', (req, res) => {
    const cardID = req.params.cardID;
    const url = `https://teakresourcescoj8.kanbanize.com/api/v2/cards/${cardID}`;
    handleProxyRequest(req, res, url, 'DELETE');
});

app.get('/proxy/boards', (req, res) => {
    const url = `https://teakresourcescoj8.kanbanize.com/api/v2/boards`;
    handleProxyRequest(req, res, url, 'GET');
});

app.get('/proxy/boards/:boardID/columns', (req, res) => {
    const boardID = req.params.boardID;
    const url = `https://teakresourcescoj8.kanbanize.com/api/v2/boards/${boardID}/columns`;
    handleProxyRequest(req, res, url, 'GET');
});

app.get('/proxy/boards/:boardID/workflows', (req, res) => {
    const boardID = req.params.boardID;
    const url = `https://teakresourcescoj8.kanbanize.com/api/v2/boards/${boardID}/workflows`;
    handleProxyRequest(req, res, url, 'GET');
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});