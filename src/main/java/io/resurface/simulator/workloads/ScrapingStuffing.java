// © 2016-2024 Graylog, Inc.

package io.resurface.simulator.workloads;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.resurface.ndjson.HttpMessage;
import io.resurface.ndjson.HttpMessages;
import io.resurface.simulator.Clock;
import io.resurface.simulator.Workload;
import net.datafaker.Faker;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Generates randomized REST messages including scraping and stuffing attacks.
 */
public class ScrapingStuffing implements Workload {

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
            if (chance < 25) {
                session_request_address = faker.internet().getPrivateIpV4Address().getHostAddress();
            } else if (chance < 90) {
                session_request_address = faker.internet().getPublicIpV4Address().getHostAddress();
            } else {
                session_request_address = attacker_addresses[(int) (Math.random() * attacker_addresses.length)];
            }
            if (chance < 40) {
                session_user_agent = faker.internet().botUserAgentAny();
            } else {
                session_user_agent = faker.internet().userAgent();
            }
            session_index = 0;
        }

        // re-set Faker seed using request_address
        if (which_attacker() < 2) {
            faker.random().getRandomInternal().setSeed(seed_from_address(session_request_address));
        } else {
            // except for specific attackers that perform scraping (res) / stuffing (req) attacks
            faker = randomFaker;
        }

        // add request details
        m.set_request_address(session_request_address);
        m.set_request_body(MAPPER.writeValueAsString(get_request_body(get_random() < 5)));
        m.set_request_content_type(CONTENT_TYPE_JSON);
        m.set_request_method(get_random() < 75 ? "GET" : "POST");
        m.set_request_url(get_random_url());
        m.set_request_user_agent(session_user_agent);

        // add response details
        m.set_interval_millis(get_random_interval());
        m.set_response_body(MAPPER.writeValueAsString(get_response_body(get_random() < 25)));
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
    ObjectNode get_request_body(boolean with_pii) {
        ObjectNode b = MAPPER.createObjectNode();

        b.put("account_id", faker.internet().uuid());
        b.put("first_name", faker.name().firstName());
        if (with_pii) {
            b.put("last_name", faker.name().lastName());
            b.put("email", faker.internet().emailAddress());
            b.put("password", faker.internet().password());
            b.put("phone_number", faker.phoneNumber().phoneNumber());
            b.put("ssn", faker.idNumber().ssnValid());
            b.put("passport", faker.passport().valid());
            b.put("driving_license", faker.drivingLicense().drivingLicense("CO"));

            ObjectNode k = MAPPER.createObjectNode();
            k.put("credit_card", faker.finance().creditCard());
            k.put("routing_number", faker.finance().usRoutingNumber());
            k.put("iban", faker.finance().iban());
            b.put("banking_details", k);
        }

        ObjectNode a = MAPPER.createObjectNode();
        if (with_pii) {
            a.put("address_street", faker.address().streetAddress());
            a.put("address_zipcode", faker.address().zipCode());
        }
        a.put("address_city", faker.address().city());
        a.put("address_state", faker.address().state());
        a.put("address_country", faker.address().country());
        b.put("address", a);

        b.put("company_name", faker.company().name());
        b.put("company_url", faker.company().url());
        b.put("handle_github", faker.bothify("github.com/??##.??##"));
        b.put("handle_linkedin", faker.bothify("linkedin.com/??##.??##"));
        b.put("handle_twitter", faker.bothify("@??##??##"));
        b.put("preferred_currency", faker.money().currencyCode());
        b.put("programming_language", faker.programmingLanguage().name());
        b.put("title", faker.job().title());

        ObjectNode f = MAPPER.createObjectNode();
        f.put("favorite_artist", faker.artist().name());
        f.put("favorite_animal", faker.animal().name());
        f.put("favorite_book", faker.book().title());
        f.put("favorite_dog", faker.dog().breed());
        f.put("favorite_pokemon", faker.pokemon().name());
        b.put("favorites", f);

        // more pii
        if (with_pii) {
            b.put("vehicle_identification_number", faker.vehicle().vin());
            b.put("mac_address", faker.internet().macAddress());
            b.put("imei", faker.code().imei());
            b.put("sin", faker.sip().nameAddress());
            b.put("cnpj", faker.cnpj().valid());
            b.put("cpf", faker.cpf().valid());
        }

        return b;
    }

    /**
     * Returns random response body.
     */
    ObjectNode get_response_body(boolean with_pii) throws Exception {
        ObjectNode b = MAPPER.createObjectNode();
        b.put("receipt_id", faker.internet().uuid());
        b.put("invoice_number", faker.internet().uuid());
        b.put("recovery_key", faker.color().name() + ":" + faker.beer().name() + ":" + faker.lebowski().character() + ":" + faker.space().galaxy());
        b.put("special_instructions", faker.lorem().paragraph(4));
        b.put("payment_total", faker.numerify("###.##"));
        b.put("payment_tax", faker.numerify("##.##"));
        b.put("contract_filename", faker.file().fileName());
        b.put("contract_filename_sha512", faker.hashing().sha512());
        b.put("future_order_discount_code", faker.random().hex(32));
        if (with_pii) {
            b.put("order_id", faker.internet().uuid());
            b.put("latitude", faker.address().latitude());
            b.put("longitude", faker.address().longitude());
        }
        b.put("lebowski_quote", faker.lebowski().quote());
        b.put("support_contact", faker.funnyName().name());
        return b;
    }

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

    private long seed_from_address(String address) {
        double res = 0;
        String[] octets = address.split("\\.");
        for (int i = 0; i < octets.length; i++) {
            int octet = Integer.parseInt(octets[i]);
            res += octet * Math.pow(256, i);
        }
        return (long) res;
    }

    private int which_attacker() {
        for (int i = 0; i < attacker_addresses.length; i++) {
            if (attacker_addresses[i].equals(session_request_address)) return i;
        }
        return -1;
    }

    final DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
    final Faker randomFaker = new Faker();
    Faker faker = randomFaker;
    int session_index = -1;
    String session_request_address;
    String session_user_agent;
    final String[] attacker_addresses = {"123.123.123.123", "205.87.214.29", "192.168.83.193", "80.163.137.141"};

}
