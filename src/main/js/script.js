var app = new Vue({
    el: '#app',
    data: {
        cards: [],
        connected: false,
        ip: "127.0.0.1:15674",
        spValue: 'GOV1',
    },
    methods: {
        reconnect: function (event) {
            if (ws.readyState != ws.OPEN) {
                ws = new WebSocket('ws://' + app.ip + '/ws');
                client = Stomp.over(ws);
            }
            if (!client.connected) {
                client.connect('guest', 'guest', on_connect, on_error, '/');
            }
        },
        setSP: function (data) {
            client.send("sp", null, data);
            app.spValue = data;
        }
    }
});

var ws = new WebSocket('ws://' + app.ip + '/ws');
var client = Stomp.over(ws);

var on_connect = function () {
    console.log('connected');

    app.connected = true;

    cards = subscribeToQueue("/exchange/amq.topic/card", app.cards);
    //symptoms = subscribeToQueueWithoutFilter( "/exchange/stats/symptom.*", app.symptoms);
    //diagnoses = subscribeToQueueWithoutFilter( "/exchange/stats/diagnosis.*", app.diagnoses);
};
var on_error = function () {
    console.log('error');

    app.connected = false;
};

function subscribeToQueue(name, dict) {
    return client.subscribe(name, function (d) {
        let json = JSON.parse(d.body);
        dict.push(json);
        //Vue.set(dict, d, json)
    });
}

client.connect('guest', 'guest', on_connect, on_error, '/');