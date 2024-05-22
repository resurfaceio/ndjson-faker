// © 2016-2024 Graylog, Inc.

package io.resurface.simulator.workloads;

import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Generates small randomized REST messages.
 */
public class RestSmall3 extends RestAbstract3 {

    @Override
    ObjectNode get_request_body() throws Exception {
        ObjectNode b = MAPPER.createObjectNode();

        b.put("account_id", faker.internet().uuid());
        b.put("first_name", faker.name().firstName());
        b.put("last_name", faker.name().lastName());
        b.put("credit_card", faker.finance().creditCard());
        b.put("email", faker.internet().emailAddress());
        b.put("password", faker.internet().password());
        b.put("phone_number", faker.phoneNumber().phoneNumber());

        ObjectNode a = MAPPER.createObjectNode();
        a.put("address_street", faker.address().streetAddress());
        a.put("address_city", faker.address().city());
        a.put("address_state", faker.address().state());
        a.put("address_zipcode", faker.address().zipCode());
        a.put("address_country", faker.address().country());
        b.put("address", a);

        b.put("company_name", faker.company().name());
        b.put("company_url", faker.company().url());
        b.put("handle_github", faker.bothify("github.com/??##.??##"));
        b.put("handle_linkedin", faker.bothify("linkedin.com/??##.??##"));
        b.put("handle_twitter", faker.bothify("@??##??##"));
        b.put("preferred_currency", faker.currency().code());
        b.put("programming_language", faker.programmingLanguage().name());
        b.put("title", faker.job().title());

        ObjectNode f = MAPPER.createObjectNode();
        f.put("favorite_artist", faker.artist().name());
        f.put("favorite_animal", faker.animal().name());
        f.put("favorite_book", faker.book().title());
        f.put("favorite_dog", faker.dog().breed());
        f.put("favorite_pokemon", faker.pokemon().name());
        b.put("favorites", f);

        return b;
    }

    @Override
    ObjectNode get_response_body() throws Exception {
        ObjectNode b = MAPPER.createObjectNode();
        b.put("receipt_id", faker.internet().uuid());
        b.put("invoice_number", faker.internet().uuid());
        b.put("recovery_key", faker.color().name() + ":" + faker.beer().name() + ":" + faker.lebowski().character() + ":" + faker.space().galaxy());
        b.put("special_instructions", faker.lorem().paragraph(4));
        b.put("payment_total", faker.numerify("###.##"));
        b.put("payment_tax", faker.numerify("##.##"));
        b.put("contract_filename", faker.file().fileName());
        b.put("contract_filename_sha512", faker.crypto().sha512());
        b.put("future_order_discount_code", faker.random().hex(32));
        b.put("latitude", faker.address().latitude());
        b.put("longitude", faker.address().longitude());
        b.put("lebowski_quote", faker.lebowski().quote());
        b.put("support_contact", faker.funnyName().name());
        return b;
    }

}
