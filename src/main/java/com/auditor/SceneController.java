package com.auditor;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;

public class SceneController {

    private JPanel mainPanel;
    private JTextField urlTextField;
    private JButton scanButton;
    private JTextArea resultTextArea;

    public SceneController() {
        initComponents();
        setupLayout();
        setupActionListener();
    }

    private void initComponents() {
        mainPanel = new JPanel();
        urlTextField = new JTextField("Введите URL сайта");
        scanButton = new JButton("Сканировать");
        resultTextArea = new JTextArea();
        resultTextArea.setEditable(false);
        resultTextArea.setBackground(Color.BLACK);
        resultTextArea.setForeground(Color.GREEN);
        resultTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
    }

    private void setupLayout() {
        mainPanel.setLayout(new BorderLayout());
        JPanel inputPanel = new JPanel(new FlowLayout());
        inputPanel.add(urlTextField);
        inputPanel.add(scanButton);

        mainPanel.add(inputPanel, BorderLayout.NORTH);
        mainPanel.add(new JScrollPane(resultTextArea), BorderLayout.CENTER);

        urlTextField.setPreferredSize(new Dimension(400, 25));
    }

    private void setupActionListener() {
        scanButton.addActionListener(e -> {
            String url = urlTextField.getText();
            if (url != null && !url.trim().isEmpty() && !url.equals("Введите URL сайта")) {
                // Trim whitespace first
                String cleanedUrl = url.trim();
                // Basic URL protocol check
                if (!cleanedUrl.startsWith("http://") && !cleanedUrl.startsWith("https://")) {
                    cleanedUrl = "http://" + cleanedUrl;
                }
                final String finalUrl = cleanedUrl; // Need final variable for the thread

                resultTextArea.append("Сканирование сайта: " + finalUrl + "\n");
                new Thread(() -> {
                    try {
                        String htmlContent = fetchHtmlContent(finalUrl);
                        Set<String> libraries = identifyLibraries(htmlContent);
                        resultTextArea.append("Обнаруженные библиотеки/фреймворки: " + libraries + "\n");

                        // Basic SQL Injection Check
                        checkSqlInjection(finalUrl);
                        checkXss(finalUrl);
                        checkCsrf(htmlContent);

                        resultTextArea.append("Сканирование завершено для: " + finalUrl + "\n");
                    } catch (IOException | URISyntaxException ex) {
                        resultTextArea.append("Ошибка при сканировании: " + ex.getMessage() + "\n");
                    }
                }).start();
            } else {
                resultTextArea.append("Пожалуйста, введите URL сайта.\n");
            }
        });
    }

    public JPanel getMainPanel() {
        return mainPanel;
    }

    private String fetchHtmlContent(String url) throws IOException {
        // Trim whitespace from the URL
        String trimmedUrl = url.trim();
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(trimmedUrl);
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                return EntityUtils.toString(response.getEntity());
            }
        }
    }

    private Set<String> identifyLibraries(String htmlContent) {
        Set<String> libraries = new HashSet<>();
        Document doc = Jsoup.parse(htmlContent);

        // Look for script tags with src attributes
        Elements scriptElements = doc.select("script[src]");
        for (Element script : scriptElements) {
            String src = script.attr("src");
            if (!src.isEmpty()) {
                libraries.add("Script: " + extractFilenameFromUrl(src));
            }
        }

        // Look for link tags with href attributes (for CSS frameworks)
        Elements linkElements = doc.select("link[href]");
        for (Element link : linkElements) {
            String href = link.attr("href");
            if (!href.isEmpty()) {
                libraries.add("Stylesheet: " + extractFilenameFromUrl(href));
            }
        }

        // TODO: Add more sophisticated logic to identify libraries from filenames or content

        return libraries;
    }

    private String extractFilenameFromUrl(String url) {
        try {
            URI uri = new URI(url);
            String path = uri.getPath();
            if (path != null && !path.isEmpty()) {
                return path.substring(path.lastIndexOf('/') + 1);
            }
        } catch (URISyntaxException e) {
            // Ignore URI syntax errors
        }
        return url; // Return original URL if filename extraction fails
    }

    private void checkSqlInjection(String url) throws IOException, URISyntaxException {
        URI uri = new URI(url);
        String query = uri.getQuery();

        if (query != null) {
            String[] params = query.split("&");
            String[] payloads = {"'", "''", "\"", "\"\"", " OR '1'='1", " OR '1'='1'--", " UNION SELECT null, null--"};

            for (String param : params) {
                String[] keyValue = param.split("=");
                if (keyValue.length == 2) {
                    String key = keyValue[0];
                    String value = keyValue[1];

                    for (String payload : payloads) {
                        String testUrl = url.replace(param, key + "=" + value + payload);
                        try {
                            String response = fetchHtmlContent(testUrl);
                            // Basic check for SQL errors in the response
                            if (response.contains("SQL syntax") || response.contains("mysql_fetch_array") || response.contains("ORA-")) {
                                resultTextArea.append("Возможная SQL-инъекция обнаружена:\n");
                                resultTextArea.append("  URL: " + testUrl + "\n");
                                resultTextArea.append("  Полезная нагрузка: " + payload + "\n");
                            }
                        } catch (IOException e) {
                            // Ignore network errors for this basic check
                        }
                    }
                }
            }
        }
    }

    private void checkXss(String url) throws IOException, URISyntaxException {
        URI uri = new URI(url);
        String query = uri.getQuery();

        if (query != null) {
            String[] params = query.split("&");
            String[] payloads = {"<script>alert('XSS')</script>", "\"><script>alert('XSS')</script>"};

            for (String param : params) {
                String[] keyValue = param.split("=");
                if (keyValue.length == 2) {
                    String key = keyValue[0];
                    String value = keyValue[1];

                    for (String payload : payloads) {
                        String testUrl = url.replace(param, key + "=" + value + payload);
                        try {
                            String response = fetchHtmlContent(testUrl);
                            // Basic check if the payload is reflected in the response
                            if (response.contains(payload)) {
                                resultTextArea.append("Возможная XSS обнаружена:\n");
                                resultTextArea.append("  URL: " + testUrl + "\n");
                                resultTextArea.append("  Полезная нагрузка: " + payload + "\n");
                            }
                        } catch (IOException e) {
                            // Ignore network errors
                        }
                    }
                }
            }
        }
    }

    private void checkCsrf(String htmlContent) {
        Document doc = Jsoup.parse(htmlContent);
        Elements forms = doc.select("form");

        boolean csrfTokenFound = false;
        for (Element form : forms) {
            Elements hiddenInputs = form.select("input[type=hidden]");
            for (Element input : hiddenInputs) {
                String name = input.attr("name");
                if (name != null && (name.contains("csrf") || name.contains("token"))) {
                    resultTextArea.append("Обнаружен потенциальный CSRF-токен в форме:\n");
                    resultTextArea.append("  Имя поля: " + name + "\n");
                    csrfTokenFound = true;
                    // For basic check, we just report finding one and stop for this form
                    break;
                }
            }
        }

        if (!csrfTokenFound) {
            resultTextArea.append("Базовая проверка на CSRF: Потенциальные CSRF-токены не обнаружены в формах. Сайт может быть уязвим.\n");
        } else {
             resultTextArea.append("Базовая проверка на CSRF: Обнаружены потенциальные CSRF-токены. Сайт, вероятно, защищен от базовых CSRF-атак.\n");
        }
    }
}
