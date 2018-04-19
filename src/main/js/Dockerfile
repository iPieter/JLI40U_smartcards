FROM rabbitmq

RUN rabbitmq-plugins enable --offline rabbitmq_management
RUN rabbitmq-plugins enable --offline rabbitmq_stomp
RUN rabbitmq-plugins enable --offline rabbitmq_web_stomp
RUN rabbitmq-plugins enable --offline rabbitmq_amqp1_0

EXPOSE 15671 15672 15674 61613
EXPOSE 1883
EXPOSE 8883
EXPOSE 5672

