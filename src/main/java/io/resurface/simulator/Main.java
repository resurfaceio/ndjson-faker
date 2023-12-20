// © 2016-2023 Graylog, Inc.

package io.resurface.simulator;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.zip.DeflaterOutputStream;

/**
 * Imports data to Resurface database.
 */
public class Main {

    /**
     * Runs utility as command-line program.
     */
    public static void main(String[] args) throws Exception {
        new Main();
    }

    /**
     * Generates simulated NDJSON messages until stopped or terminated.
     */
    public Main() throws Exception {
        // calculate destination url if not provided
        String url = System.getProperty("URL");
        if (url == null) {
            String host = System.getProperty("HOST");
            if (host == null) host = "localhost";
            System.out.println("HOST=" + host);
            String port = System.getProperty("PORT");
            if (port == null) port = "7701";
            System.out.println("PORT=" + port);
            if (port.equals("80") || port.equals("443")) {
                url = (port.equals("443") ? "https://" : "http://") + host + "/fluke/message";
            } else {
                url = "http://" + host + ":" + port + "/message";
            }
        }
        System.out.println("URL=" + url);
        parsed_url = new URL(url);

        // read runtime options
        int clock_skew_days = Integer.parseInt(System.getProperty("CLOCK_SKEW_DAYS", "0"));
        System.out.println("CLOCK_SKEW_DAYS=" + clock_skew_days);
        limit_messages = Long.parseLong(System.getProperty("LIMIT_MESSAGES", "0"));
        System.out.println("LIMIT_MESSAGES=" + limit_messages);
        limit_millis = Long.parseLong(System.getProperty("LIMIT_MILLIS", "0"));
        System.out.println("LIMIT_MILLIS=" + limit_millis);
        int sleep_per_batch = Integer.parseInt(System.getProperty("SLEEP_PER_BATCH", "0"));
        System.out.println("SLEEP_PER_BATCH=" + sleep_per_batch);

        // validate runtime options
        if (clock_skew_days > 0 && sleep_per_batch > 0) {
            System.out.println("CLOCK_SKEW_DAYS and SLEEP_PER_BATCH are exclusive options, please use one or the other 😀");
            System.exit(-1);
        }

        // create workload
        String workload_name = System.getProperty("WORKLOAD", "Coinbroker");
        Workload workload = (Workload) Class.forName("io.resurface.simulator.workloads." + workload_name).getConstructor().newInstance();

        // create thread to send batches asynchronously
        new Thread(new BatchSender()).start();

        // create simulation clock
        clock = new Clock(clock_skew_days);
        new Thread(clock).start();

        // send messages until workload is finished
        List<String> batch = new ArrayList<>(MIN_BATCH_SIZE);
        while (true) {
            int size_before = batch.size();
            workload.add(batch, clock);
            int size = batch.size();
            if (size == size_before) {
                break;
            } else if (size > MIN_BATCH_SIZE) {
                batch_queue.put(new ArrayList<>(batch));
                batch.clear();
                if (sleep_per_batch > 0) Thread.sleep(sleep_per_batch);
            }
        }

        // signal sender thread to stop via poison
        batch_queue.put(POISON_BATCH);
    }

    /**
     * Worker thread that sends batches of messages.
     */
    class BatchSender implements Runnable {

        public void run() {
            try {
                while (true) {
                    List<String> b = batch_queue.take();

                    // exit if poisoned
                    if (b == POISON_BATCH) System.exit(0);

                    // make request to database
                    HttpURLConnection c = (HttpURLConnection) parsed_url.openConnection();
                    c.setConnectTimeout(5000);
                    c.setReadTimeout(5000);
                    c.setRequestMethod("POST");
                    c.setRequestProperty("Content-Encoding", "deflated");
                    c.setRequestProperty("Content-Type", "application/ndjson; charset=UTF-8");
                    c.setRequestProperty("User-Agent", "Resurface/v3.6.x (simulator)");
                    c.setDoOutput(true);
                    try (OutputStream os = c.getOutputStream()) {
                        try (DeflaterOutputStream dos = new DeflaterOutputStream(os, true)) {
                            for (String m : b) {
                                dos.write(m.getBytes(StandardCharsets.UTF_8));
                                dos.write("\n".getBytes(StandardCharsets.UTF_8));
                            }
                            dos.finish();
                            dos.flush();
                        }
                        os.flush();
                    }

                    // check response from database
                    int response_code = c.getResponseCode();
                    if (response_code != 204) {
                        System.out.println("Failed with response code: " + response_code);
                        System.exit(-1);
                    }

                    // update running state
                    messages_written += b.size();
                    status();
                }
            } catch (RuntimeException | IOException | InterruptedException e) {
                e.printStackTrace();
                System.exit(-1);
            }
        }

    }

    /**
     * Print status summary.
     */
    private void status() {
        long now = System.currentTimeMillis();
        long elapsed = now - started;
        long rate = (messages_written * 1000 / elapsed);
        System.out.println("Messages: " + messages_written + ", Elapsed time: " + elapsed + " ms, Rate: " + rate + " msg/sec");

        // exit if limits reached
        if (clock.now() > now + 5000) System.exit(0);
        if ((limit_messages > 0) && (messages_written > limit_messages)) System.exit(0);
        if ((limit_millis > 0) && (elapsed > limit_millis)) System.exit(0);
    }

    private final BlockingQueue<List<String>> batch_queue = new ArrayBlockingQueue<>(256);
    private final Clock clock;
    private final long limit_messages;
    private final long limit_millis;
    private long messages_written;
    private final URL parsed_url;
    private final long started = System.currentTimeMillis();

    private static final int MIN_BATCH_SIZE = 32;
    private static final List<String> POISON_BATCH = new ArrayList<>();

}