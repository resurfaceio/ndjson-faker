// © 2016-2024 Graylog, Inc.

package io.resurface.simulator.workloads;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.javafaker.Faker;
import io.resurface.ndjson.HttpMessage;
import io.resurface.ndjson.HttpMessages;
import io.resurface.simulator.Clock;
import io.resurface.simulator.Workload;

import java.util.List;

/**
 * Generates REST and GraphQL calls for the simulated 'coinbroker' API used for product demos.
 */
public class Coinbroker implements Workload {

    /**
     * Adds a single message to the batch without any stop conditions.
     */
    public void add(List<String> batch, Clock clock, String dialect) throws Exception {
        String account_token = faker.internet().uuid();
        String coin_type = get_coin_type();
        String first_name = faker.name().firstName();
        String last_name = faker.name().lastName();
        String email = faker.internet().emailAddress();
        boolean use_graphql = (Math.random() * 100) > 70;
        long now = clock.now();

        // start session
        HttpMessage m = new HttpMessage();
        m.set_request_address(faker.internet().ipV4Address());
        m.set_request_content_type(CONTENT_TYPE_JSON);
        m.set_request_user_agent(get_user_agent());
        m.set_response_code("200");
        m.set_response_content_type(CONTENT_TYPE_JSON);

        // write registration message
        m.set_request_method("POST");
        ObjectNode request_body = MAPPER.createObjectNode();
        ObjectNode response_body = MAPPER.createObjectNode();
        if (use_graphql) {
            m.set_request_url("https://coinbroker.io/graphql");
            String graphql_query = String.format("""
                    mutation { createUser(
                    first_name: "%s",
                    last_name: "%s",
                    email: "%s"
                    )}""", first_name, last_name, email);
            request_body.put("query", graphql_query);
            ObjectNode response_data = MAPPER.createObjectNode();
            response_data.put("account_token", account_token);
            response_body.put("data", response_data);
        } else {
            m.set_request_url("https://coinbroker.io/user");
            request_body.put("first_name", first_name);
            request_body.put("last_name", last_name);
            request_body.put("email", email);
            response_body.put("account_token", account_token);
        }
        m.set_response_time_millis(++now);
        batch.add(finish(m, request_body, response_body, use_graphql, dialect));

        // write one or more quote messages
        String quote_token = faker.internet().uuid();
        int quotes = (int) (Math.random() * 6);
        for (int i = 0; i < quotes; i++) {
            int amount = get_random();
            double coin = (coin_type.equals("BTC") ? amount * 0.000045 : amount * 0.0042);
            quote_token = faker.internet().uuid();
            request_body = MAPPER.createObjectNode();
            response_body = MAPPER.createObjectNode();
            if (use_graphql) {
                m.set_request_method("POST");
                m.set_request_url("https://coinbroker.io/graphql");
                String graphql_query = String.format("""
                        query { quote(
                        account_token: "%s",
                        amount_usd: "%s",
                        coin_type: "%s"
                        )}""", account_token, amount, coin_type);
                request_body.put("query", graphql_query);
                ObjectNode response_data = MAPPER.createObjectNode();
                response_data.put("amount_usd", amount);
                response_data.put("coin", coin);
                response_data.put("coin_type", coin_type);
                response_data.put("quote_token", quote_token);
                response_data.put("valid_until", System.currentTimeMillis() + 7200000);
                response_body.put("data", response_data);
            } else {
                m.set_request_method("GET");
                m.set_request_url("https://coinbroker.io/quote");
                request_body.put("account_token", account_token);
                request_body.put("amount_usd", amount);
                request_body.put("coin_type", coin_type);
                response_body.put("amount_usd", amount);
                response_body.put("coin", coin);
                response_body.put("coin_type", coin_type);
                response_body.put("quote_token", quote_token);
                response_body.put("valid_until", System.currentTimeMillis() + 7200000);
            }
            m.set_response_time_millis(++now);
            batch.add(finish(m, request_body, response_body, use_graphql, dialect));
        }

        // write order message
        m.set_request_method("POST");
        request_body = MAPPER.createObjectNode();
        response_body = MAPPER.createObjectNode();
        if (use_graphql) {
            m.set_request_url("https://coinbroker.io/graphql");
            String graphql_query = String.format("""
                    mutation { createOrder(
                    account_token: "%s",
                    quote_token: "%s"
                    )}""", account_token, quote_token);
            request_body.put("query", graphql_query);
            ObjectNode response_data = MAPPER.createObjectNode();
            response_data.put("quote_token", quote_token);
            response_data.put("time_processed", System.currentTimeMillis());
            response_body.put("data", response_data);
        } else {
            m.set_request_url("https://coinbroker.io/order");
            request_body.put("account_token", account_token);
            request_body.put("quote_token", quote_token);
            response_body.put("quote_token", quote_token);
            response_body.put("time_processed", System.currentTimeMillis());
        }
        m.set_response_time_millis(++now);
        batch.add(finish(m, request_body, response_body, use_graphql, dialect));
    }

    /**
     * Finishes message and returns as a string.
     */
    private String finish(HttpMessage m, ObjectNode request_body, ObjectNode response_body, boolean use_graphql, String dialect) throws Exception {
        // todo add runtime failure
        // todo add attack
        m.set_interval_millis(get_interval());
        m.set_request_body(MAPPER.writeValueAsString(request_body));
        m.set_response_body(MAPPER.writeValueAsString(response_body));
        m.add_response_header("ETag", "\"" + faker.internet().uuid() + "\"");
        return HttpMessages.format(m, dialect);
    }

    /**
     * Returns randomized coin type.
     */
    private String get_coin_type() {
        int rand = get_random();
        if (rand < 80) {
            return "BTC";
        } else {
            return "LTC";
        }
    }

    /**
     * Returns random interval.
     */
    private int get_interval() {
        if (get_random() < 5) {
            return (int) (Math.random() * 30000);
        } else {
            return (int) (Math.random() * 4000);
        }
    }

    /**
     * Returns random percentage.
     */
    private int get_random() {
        return (int) (Math.random() * 100);
    }

    /**
     * Returns random user-agent.
     */
    private String get_user_agent() {
        int rand = get_random();
        if (rand < 75) {
            return "Coinbroker/5.2.4 CFNetwork/808.3 Darwin/16.3.0";
        } else {
            return "curl/1.13.4";
        }
    }

    private final Faker faker = new Faker();

}
