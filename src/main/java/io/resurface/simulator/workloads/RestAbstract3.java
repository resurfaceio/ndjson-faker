// © 2016-2024 Graylog, Inc.

package io.resurface.simulator.workloads;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.javafaker.Faker;
import io.resurface.ndjson.HttpMessage;
import io.resurface.ndjson.HttpMessages;
import io.resurface.simulator.Clock;
import io.resurface.simulator.Workload;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Generates randomized REST messages.
 */
public abstract class RestAbstract3 implements Workload {

    /**
     * Adds a single message to the batch without any stop conditions.
     */
    public void add(List<String> batch, Clock clock, String dialect) throws Exception {
        batch.add(HttpMessages.format(build(clock), dialect));
    }

    /**
     * Builds and returns a random REST message.
     */
    HttpMessage build(Clock clock) throws Exception {
        HttpMessage m = new HttpMessage();

        // update session-level fields
        if ((session_index < 0) || (++session_index > 4)) {
            int chance = get_random();
            if (chance < 99) {
                session_request_address = faker.internet().ipV4Address();
            } else {
                session_request_address = "123.123.123.123";
            }
            session_user_agent = faker.internet().userAgentAny();
            session_index = 0;
        }

        // add request details
        m.set_request_address(session_request_address);
        m.set_request_body(MAPPER.writeValueAsString(get_request_body()));
        m.set_request_content_type(CONTENT_TYPE_JSON);
        m.set_request_method(get_random() < 75 ? "GET" : "POST");
        m.set_request_url(get_random_url());
        m.set_request_user_agent(session_user_agent);

        // add response details
        m.set_interval_millis(get_random_interval());
        m.set_response_body(MAPPER.writeValueAsString(get_response_body()));
        m.set_response_code("200");
        m.set_response_content_type(CONTENT_TYPE_JSON);
        m.set_response_time_millis(clock.now());

        // add request headers
        int chance = get_random();
        if (chance < 40) build_request_headers(m, 7);
        else if (chance < 60) build_request_headers(m, 8);
        else if (chance < 80) build_request_headers(m, 6);
        else if (chance < 90) build_request_headers(m, 2);
        else if (chance < 95) build_request_headers(m, 12);
        else build_request_headers(m, 20);

        // add response headers
        chance = get_random();
        if (chance < 45) build_response_headers(m, 2);
        else if (chance < 95) build_response_headers(m, 3);
        else build_response_headers(m, 5);

        return m;
    }

    /**
     * Adds specified number of request headers to the message.
     */
    void build_request_headers(HttpMessage message, int count) {
        message.add_request_header("Session-Index", String.valueOf(session_index));
        message.add_request_header("X-Request-ID", faker.internet().uuid());
        if (count == 2) return;
        message.add_request_header("X-Forwarded-Scheme", "http");
        message.add_request_header("X-Forwarded-Port", "80");
        message.add_request_header("Accept", "*/*");
        message.add_request_header("Content-Length", String.valueOf(message.request_body() == null ? "0" : message.request_body().length()));
        if (count == 6) return;
        message.add_request_header("Accept-Encoding", "gzip");
        if (count == 7) return;
        for (int i = 7; i < count; i++) message.add_request_header(faker.bothify("app??_##??"), faker.random().hex());
    }

    /**
     * Adds specified number of response headers to the message.
     */
    void build_response_headers(HttpMessage message, int count) {
        message.add_response_header("Content-Length", String.valueOf(message.response_body() == null ? "0" : message.response_body().length()));
        message.add_request_header("X-Response-ID", faker.internet().uuid());
        if (count == 2) return;
        message.add_response_header("Date", dtf.format(LocalDateTime.now()));
        if (count == 3) return;
        message.add_response_header("X-Content-Type-Options", "nosniff");
    }

    /**
     * Returns random request body.
     */
    abstract ObjectNode get_request_body() throws Exception;

    /**
     * Returns random response body.
     */
    abstract ObjectNode get_response_body() throws Exception;

    /**
     * Returns random percentage.
     */
    int get_random() {
        return (int) (Math.random() * 100);
    }

    /**
     * Returns random interval.
     */
    private int get_random_interval() {
        if (get_random() < 5) {
            return (int) (Math.random() * 30000);
        } else {
            return (int) (Math.random() * 4000);
        }
    }

    /**
     * Returns random url.
     */
    private String get_random_url() {
        int random = get_random();
        if (random < 10) {
            return String.format("https://%s.com/.env", faker.random().hex() + faker.random().hex() + faker.random().hex());
        } else if (random < 15) {
            return "https://api.sendgrid.com/v3/mail/send";
        } else if (random < 18) {
            return "https://api.twilio.com/notification";
        } else if (random < 28) {
            return "https://app.coinbroker.io/v1/pricing";
        } else if (random < 44) {
            return "https://graphql.coinbroker.io/graphql";
        } else if (random < 87) {
            return String.format("https://app.coinbroker.io/v1/quote/%s/", faker.internet().uuid());
        } else {
            return String.format("https://app.coinbroker.io/v1/purchase/%s/", faker.internet().uuid());
        }
    }

    final DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
    final Faker faker = new Faker();
    int session_index = -1;
    String session_request_address;
    String session_user_agent;

}
