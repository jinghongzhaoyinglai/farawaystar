import java.net.InetAddress;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class backend {
    private static Map<String, String> users = new ConcurrentHashMap<>();
    private static Map<String, String> sessions = new ConcurrentHashMap<>();
    private static Map<String, UserData> userData = new ConcurrentHashMap<>();
    private static List<LeaderboardEntry> leaderboard = new ArrayList<>();
    private static final String USER_DATA_FILE = "users.dat";
    private static final String GAME_DATA_FILE = "game_data.dat";
    private static final String LEADERBOARD_FILE = "leaderboard.dat";

    // 用户游戏数据类
    static class UserData implements Serializable {
        String username;
        int highScore;
        int currentScore;
        List<FruitState> fruits;
        int nextFruitType;
        boolean isGameOver;

        UserData(String username) {
            this.username = username;
            this.highScore = 0;
            this.currentScore = 0;
            this.fruits = new ArrayList<>();
            this.nextFruitType = 0;
            this.isGameOver = false;
        }
    }

    // 水果状态类
    static class FruitState implements Serializable {
        int type;
        double x, y;
        double vx, vy;
        double radius;
        boolean isDropped;

        FruitState(int type, double x, double y, double vx, double vy, double radius, boolean isDropped) {
            this.type = type;
            this.x = x;
            this.y = y;
            this.vx = vx;
            this.vy = vy;
            this.radius = radius;
            this.isDropped = isDropped;
        }
    }

    // 排行榜条目
    static class LeaderboardEntry implements Serializable {
        String username;
        int score;
        long timestamp;

        LeaderboardEntry(String username, int score) {
            this.username = username;
            this.score = score;
            this.timestamp = System.currentTimeMillis();
        }
    }

    public static void main(String[] args) throws IOException {
        // 加载用户数据
        loadUsers();
        loadGameData();
        loadLeaderboard();

        // 创建HTTP服务器
	String port = System.getenv("PORT");
    	if (port == null) {
        	port = "8080";
    	}
    
    	// 创建HTTP服务器
   	HttpServer server = HttpServer.create(new InetSocketAddress(Integer.parseInt(port)), 0);

        // 设置路由
        server.createContext("/", new StaticHandler());
        server.createContext("/api/login", new LoginHandler());
        server.createContext("/api/register", new RegisterHandler());
        server.createContext("/api/logout", new LogoutHandler());
        server.createContext("/api/checkAuth", new AuthCheckHandler());
        server.createContext("/api/updateGame", new UpdateGameHandler());
        server.createContext("/api/saveScore", new SaveScoreHandler());
        server.createContext("/api/leaderboard", new LeaderboardHandler());

        server.setExecutor(null);
        server.start();

        System.out.println("服务器启动在 http://localhost:8080");
        System.out.println("请访问 http://localhost:8080");
    }

    // 加载用户数据
    private static void loadUsers() {
        try {
            File file = new File(USER_DATA_FILE);
            if (file.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(file));
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(":");
                    if (parts.length == 2) {
                        users.put(parts[0], parts[1]);
                    }
                }
                reader.close();
                System.out.println("已加载 " + users.size() + " 个用户");
            } else {
                users.put("admin", "admin123");
                users.put("user", "user123");
                saveUsers();
                System.out.println("创建默认测试用户");
            }
        } catch (IOException e) {
            System.out.println("加载用户数据失败: " + e.getMessage());
            users.put("admin", "admin123");
            users.put("user", "user123");
        }
    }

    // 加载游戏数据
    private static void loadGameData() {
        try {
            File file = new File(GAME_DATA_FILE);
            if (file.exists()) {
                ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file));
                userData = (ConcurrentHashMap<String, UserData>) ois.readObject();
                ois.close();
                System.out.println("已加载 " + userData.size() + " 个用户的游戏数据");
            }
        } catch (Exception e) {
            System.out.println("加载游戏数据失败: " + e.getMessage());
            userData = new ConcurrentHashMap<>();
        }
    }

    // 加载排行榜
    private static void loadLeaderboard() {
        try {
            File file = new File(LEADERBOARD_FILE);
            if (file.exists()) {
                ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file));
                leaderboard = (ArrayList<LeaderboardEntry>) ois.readObject();
                ois.close();
                System.out.println("已加载排行榜数据，共 " + leaderboard.size() + " 条记录");
            }
        } catch (Exception e) {
            System.out.println("加载排行榜失败: " + e.getMessage());
            leaderboard = new ArrayList<>();
        }
    }

    // 保存用户数据
    private static void saveUsers() {
        try {
            PrintWriter writer = new PrintWriter(new FileWriter(USER_DATA_FILE));
            for (Map.Entry<String, String> entry : users.entrySet()) {
                writer.println(entry.getKey() + ":" + entry.getValue());
            }
            writer.close();
        } catch (IOException e) {
            System.out.println("保存用户数据失败: " + e.getMessage());
        }
    }

    // 保存游戏数据
    private static void saveGameData() {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(GAME_DATA_FILE));
            oos.writeObject(userData);
            oos.close();
        } catch (IOException e) {
            System.out.println("保存游戏数据失败: " + e.getMessage());
        }
    }

    // 保存排行榜
    private static void saveLeaderboard() {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(LEADERBOARD_FILE));
            oos.writeObject(leaderboard);
            oos.close();
        } catch (IOException e) {
            System.out.println("保存排行榜失败: " + e.getMessage());
        }
    }

    // 获取用户数据
    private static UserData getUserData(String username) {
        return userData.computeIfAbsent(username, k -> new UserData(username));
    }

    // 更新排行榜 - 只在创造新高且超越现有记录时添加
    private static boolean updateLeaderboard(String username, int score) {
        // 检查是否已经存在于排行榜中
        for (LeaderboardEntry entry : leaderboard) {
            if (entry.username.equals(username)) {
                if (score > entry.score) {
                    entry.score = score;
                    entry.timestamp = System.currentTimeMillis();
                    // 重新排序
                    leaderboard.sort((a, b) -> b.score - a.score);
                    saveLeaderboard();
                    return true;
                }
                return false;
            }
        }

        // 新用户，检查是否足够进入排行榜
        if (leaderboard.size() < 10) {
            // 排行榜未满，直接添加
            leaderboard.add(new LeaderboardEntry(username, score));
        } else {
            // 检查分数是否超过排行榜最低分
            int minScore = leaderboard.get(leaderboard.size() - 1).score;
            if (score > minScore) {
                leaderboard.remove(leaderboard.size() - 1);
                leaderboard.add(new LeaderboardEntry(username, score));
            } else {
                return false;
            }
        }

        // 按分数排序
        leaderboard.sort((a, b) -> b.score - a.score);
        saveLeaderboard();
        return true;
    }

    // 静态文件处理器
    static class StaticHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                String path = exchange.getRequestURI().getPath();
                if ("/".equals(path)) {
                    serveHtmlFile(exchange);
                } else {
                    sendResponse(exchange, 404, "{\"error\": \"Not Found\"}");
                }
            } else {
                sendResponse(exchange, 405, "{\"error\": \"Method Not Allowed\"}");
            }
        }

        private void serveHtmlFile(HttpExchange exchange) throws IOException {
            try {
                File htmlFile = new File("./frontend.html");

                if (!htmlFile.exists()) {
                    sendResponse(exchange, 404, "{\"error\": \"HTML file not found at: " +
                            htmlFile.getAbsolutePath() + "\"}");
                    return;
                }

                System.out.println("正在服务HTML文件: " + htmlFile.getAbsolutePath());
                byte[] htmlContent = readFile(htmlFile);
                exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
                exchange.sendResponseHeaders(200, htmlContent.length);
                OutputStream os = exchange.getResponseBody();
                os.write(htmlContent);
                os.close();
            } catch (Exception e) {
                sendResponse(exchange, 500, "{\"error\": \"Server error: " + e.getMessage() + "\"}");
                e.printStackTrace();
            }
        }

        private byte[] readFile(File file) throws IOException {
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            return data;
        }
    }

    // 更新游戏状态处理器
    static class UpdateGameHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                try {
                    String requestBody = readRequestBody(exchange);
                    Map<String, String> gameData = parseJson(requestBody);
//                    System.out.println();
                    String sessionId = gameData.get("sessionId");
                    String username = sessions.get(sessionId);

                    if (username == null) {
                        sendResponse(exchange, 401, "{\"error\": \"未登录\"}");
                        return;
                    }
                    // 添加简洁的水果数据检查日志

                    String fruitsData = gameData.get("fruits");
//                    System.out.println(fruitsData);
                    UserData userData = getUserData(username);
                    userData.currentScore = Integer.parseInt(gameData.get("currentScore"));
                    userData.nextFruitType = Integer.parseInt(gameData.get("nextFruitType"));
                    userData.isGameOver = Boolean.parseBoolean(gameData.get("isGameOver"));
                    // 解析水果状态
                    userData.fruits.clear();
                    if (fruitsData != null && !fruitsData.isEmpty()) {
                        String[] fruitArray = fruitsData.split(";");
                        for (String fruitStr : fruitArray) {
                            String[] parts = fruitStr.split("#");
                            if (parts.length == 7) {
                                FruitState fruit = new FruitState(
                                        Integer.parseInt(parts[0]),
                                        Double.parseDouble(parts[1]),
                                        Double.parseDouble(parts[2]),
                                        Double.parseDouble(parts[3]),
                                        Double.parseDouble(parts[4]),
                                        Double.parseDouble(parts[5]),
                                        Boolean.parseBoolean(parts[6])
                                );
                                userData.fruits.add(fruit);
                            }
                        }
                    }

                    saveGameData();

                    Map<String, String> response = new HashMap<>();
                    response.put("success", "true");
                    sendJsonResponse(exchange, 200, response);

                } catch (Exception e) {
                    Map<String, String> response = new HashMap<>();
                    response.put("success", "false");
                    response.put("error", "更新游戏失败: " + e.getMessage());
                    sendJsonResponse(exchange, 500, response);
                }
            } else {
                sendResponse(exchange, 405, "{\"error\": \"Method Not Allowed\"}");
            }
        }
    }

    // 保存分数处理器 - 只在创造新高且超越排行榜时添加
    static class SaveScoreHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                try {
                    String requestBody = readRequestBody(exchange);
                    Map<String, String> scoreData = parseJson(requestBody);

                    String sessionId = scoreData.get("sessionId");
                    String username = sessions.get(sessionId);
                    int score = Integer.parseInt(scoreData.get("score"));

                    if (username == null) {
                        sendResponse(exchange, 401, "{\"error\": \"未登录\"}");
                        return;
                    }

                    UserData userData = getUserData(username);
                    boolean isNewHighScore = false;
                    boolean addedToLeaderboard = false;

                    if (score > userData.highScore) {
                        userData.highScore = score;
                        isNewHighScore = true;

                        // 只在创造新高且超越排行榜时添加
                        addedToLeaderboard = updateLeaderboard(username, score);
                        saveGameData();
                        System.out.println("用户 " + username + " 创造新纪录: " + score +
                                (addedToLeaderboard ? " (已添加到排行榜)" : " (未进入排行榜)"));
                    }

                    Map<String, String> response = new HashMap<>();
                    response.put("success", "true");
                    response.put("highScore", String.valueOf(userData.highScore));
                    response.put("isNewHighScore", String.valueOf(isNewHighScore));
                    response.put("addedToLeaderboard", String.valueOf(addedToLeaderboard));
                    sendJsonResponse(exchange, 200, response);

                } catch (Exception e) {
                    Map<String, String> response = new HashMap<>();
                    response.put("success", "false");
                    response.put("error", "保存分数失败: " + e.getMessage());
                    sendJsonResponse(exchange, 500, response);
                }
            } else {
                sendResponse(exchange, 405, "{\"error\": \"Method Not Allowed\"}");
            }
        }
    }

    // 排行榜处理器
    static class LeaderboardHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                try {
                    // 构建响应
                    StringBuilder json = new StringBuilder("{\"success\":true,\"leaderboard\":[");
                    for (int i = 0; i < Math.min(10, leaderboard.size()); i++) {
                        LeaderboardEntry entry = leaderboard.get(i);
                        json.append("{\"username\":\"").append(entry.username)
                                .append("\",\"score\":").append(entry.score).append("},");
                    }
                    if (!leaderboard.isEmpty() && json.charAt(json.length()-1) == ',') {
                        json.setLength(json.length() - 1);
                    }
                    json.append("]}");

                    sendResponse(exchange, 200, json.toString());

                } catch (Exception e) {
                    sendResponse(exchange, 500, "{\"success\":false,\"error\":\"获取排行榜失败: " + e.getMessage() + "\"}");
                }
            } else {
                sendResponse(exchange, 405, "{\"error\": \"Method Not Allowed\"}");
            }
        }
    }

    // 注册处理器
    static class RegisterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                try {
                    String requestBody = readRequestBody(exchange);
                    Map<String, String> registerData = parseJson(requestBody);

                    String username = registerData.get("username");
                    String password = registerData.get("password");
                    String confirmPassword = registerData.get("confirmPassword");

                    Map<String, String> response = new HashMap<>();

                    if (username == null || username.trim().isEmpty()) {
                        response.put("success", "false");
                        response.put("error", "用户名不能为空");
                        sendJsonResponse(exchange, 400, response);
                        return;
                    }

                    if (password == null || password.trim().isEmpty()) {
                        response.put("success", "false");
                        response.put("error", "密码不能为空");
                        sendJsonResponse(exchange, 400, response);
                        return;
                    }

                    if (!password.equals(confirmPassword)) {
                        response.put("success", "false");
                        response.put("error", "两次输入的密码不一致");
                        sendJsonResponse(exchange, 400, response);
                        return;
                    }

                    if (username.length() < 3 || username.length() > 20) {
                        response.put("success", "false");
                        response.put("error", "用户名长度必须在3-20个字符之间");
                        sendJsonResponse(exchange, 400, response);
                        return;
                    }

                    if (password.length() < 6) {
                        response.put("success", "false");
                        response.put("error", "密码长度至少6个字符");
                        sendJsonResponse(exchange, 400, response);
                        return;
                    }

                    if (users.containsKey(username)) {
                        response.put("success", "false");
                        response.put("error", "用户名已存在");
                        sendJsonResponse(exchange, 400, response);
                        return;
                    }

                    users.put(username, password);
                    saveUsers();

                    response.put("success", "true");
                    response.put("message", "注册成功，请登录");
                    sendJsonResponse(exchange, 200, response);

                    System.out.println("新用户注册: " + username);

                } catch (Exception e) {
                    Map<String, String> response = new HashMap<>();
                    response.put("success", "false");
                    response.put("error", "服务器错误: " + e.getMessage());
                    sendJsonResponse(exchange, 500, response);
                }
            } else {
                sendResponse(exchange, 405, "{\"error\": \"Method Not Allowed\"}");
            }
        }
    }

    // 登录处理器
    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                try {
                    String requestBody = readRequestBody(exchange);
                    Map<String, String> loginData = parseJson(requestBody);

                    String username = loginData.get("username");
                    String password = loginData.get("password");

                    if (authenticate(username, password)) {
                        String sessionId = generateSessionId();
                        sessions.put(sessionId, username);

                        UserData userData = getUserData(username);

                        Map<String, String> response = new HashMap<>();
                        response.put("success", "true");
                        response.put("sessionId", sessionId);
                        response.put("username", username);
                        response.put("highScore", String.valueOf(userData.highScore));
                        response.put("currentScore", String.valueOf(userData.currentScore));
                        response.put("nextFruitType", String.valueOf(userData.nextFruitType));
                        response.put("isGameOver", String.valueOf(userData.isGameOver));

                        // 构建水果状态字符串
                        StringBuilder fruitsBuilder = new StringBuilder();
                        for (FruitState fruit : userData.fruits) {
                            fruitsBuilder.append(fruit.type).append("#")
                                    .append(fruit.x).append("#")
                                    .append(fruit.y).append("#")
                                    .append(fruit.vx).append("#")
                                    .append(fruit.vy).append("#")
                                    .append(fruit.radius).append("#")
                                    .append(fruit.isDropped).append(";");
                        }
                        if (fruitsBuilder.length() > 0) {
                            fruitsBuilder.setLength(fruitsBuilder.length() - 1);
                        }
                        response.put("fruits", fruitsBuilder.toString());

                        sendJsonResponse(exchange, 200, response);
                    } else {
                        Map<String, String> response = new HashMap<>();
                        response.put("success", "false");
                        response.put("error", "用户名或密码错误");
                        sendJsonResponse(exchange, 401, response);
                    }
                } catch (Exception e) {
                    Map<String, String> response = new HashMap<>();
                    response.put("success", "false");
                    response.put("error", "服务器错误: " + e.getMessage());
                    sendJsonResponse(exchange, 500, response);
                }
            } else {
                sendResponse(exchange, 405, "{\"error\": \"Method Not Allowed\"}");
            }
        }
    }

    static class LogoutHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                try {
                    String requestBody = readRequestBody(exchange);
                    Map<String, String> logoutData = parseJson(requestBody);
                    String sessionId = logoutData.get("sessionId");

                    if (sessionId != null) {
                        String username = sessions.get(sessionId);
                        if (username != null) {
                            // 在退出时保存游戏状态
                            UserData userData = getUserData(username);
                            userData.currentScore = Integer.parseInt(logoutData.get("currentScore"));
                            userData.nextFruitType = Integer.parseInt(logoutData.get("nextFruitType"));
                            userData.isGameOver = Boolean.parseBoolean(logoutData.get("isGameOver"));

                            // 保存水果状态
                            userData.fruits.clear();
                            String fruitsData = logoutData.get("fruits");
//                            System.out.println(fruitsData);
//                            System.out.println("用户 " + username + " 退出登录，水果数据: " +
//                                    (fruitsData != null && !fruitsData.isEmpty() ? fruitsData.split(";").length + " 个水果" : "无水果"));
                            if (fruitsData != null && !fruitsData.isEmpty()) {
                                String[] fruitArray = fruitsData.split(";");
                                for (String fruitStr : fruitArray) {
//                                    System.out.println();
                                    String[] parts = fruitStr.split("#");
                                    if (parts.length == 7) {
                                        FruitState fruit = new FruitState(
                                                Integer.parseInt(parts[0]),
                                                Double.parseDouble(parts[1]),
                                                Double.parseDouble(parts[2]),
                                                Double.parseDouble(parts[3]),
                                                Double.parseDouble(parts[4]),
                                                Double.parseDouble(parts[5]),
                                                Boolean.parseBoolean(parts[6])
                                        );
                                        userData.fruits.add(fruit);
                                    }
                                }
                            }

                            saveGameData();
                            System.out.println("用户 " + username + " 退出，游戏状态已保存");
                        }
                        sessions.remove(sessionId);
                    }

                    Map<String, String> response = new HashMap<>();
                    response.put("success", "true");
                    sendJsonResponse(exchange, 200, response);

                } catch (Exception e) {
                    Map<String, String> response = new HashMap<>();
                    response.put("success", "false");
                    response.put("error", "退出失败: " + e.getMessage());
                    sendJsonResponse(exchange, 500, response);
                }
            } else {
                sendResponse(exchange, 405, "{\"error\": \"Method Not Allowed\"}");
            }
        }
    }

    static class AuthCheckHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                String requestBody = readRequestBody(exchange);
                Map<String, String> authData = parseJson(requestBody);
                String sessionId = authData.get("sessionId");

                String username = sessions.get(sessionId);
                Map<String, String> response = new HashMap<>();

                if (username != null) {
                    response.put("authenticated", "true");
                    response.put("username", username);
                    UserData userData = getUserData(username);
                    response.put("highScore", String.valueOf(userData.highScore));
                } else {
                    response.put("authenticated", "false");
                }

                sendJsonResponse(exchange, 200, response);
            } else {
                sendResponse(exchange, 405, "{\"error\": \"Method Not Allowed\"}");
            }
        }
    }

    // 工具方法
    private static String readRequestBody(HttpExchange exchange) throws IOException {
        InputStream is = exchange.getRequestBody();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = is.read(buffer)) != -1) {
            bos.write(buffer, 0, bytesRead);
        }
        return bos.toString(StandardCharsets.UTF_8);
    }

    private static Map<String, String> parseJson(String json) {
        Map<String, String> result = new HashMap<>();
        if (json == null || json.trim().isEmpty()) {
            return result;
        }

        json = json.trim().replace("{", "").replace("}", "").replace("\"", "");
        String[] pairs = json.split(",");
//        System.out.println(pairs.length);
        for (String pair : pairs) {
            String[] keyValue = pair.split(":");
            if (keyValue.length == 2) {
                result.put(keyValue[0].trim(), keyValue[1].trim());
            }
        }
        return result;
    }
    private static boolean authenticate(String username, String password) {
        return username != null && password != null &&
                password.equals(users.get(username));
    }

    private static String generateSessionId() {
        return java.util.UUID.randomUUID().toString();
    }

    private static void sendJsonResponse(HttpExchange exchange, int code, Map<String, String> data) throws IOException {
        StringBuilder json = new StringBuilder("{");
        for (Map.Entry<String, String> entry : data.entrySet()) {
            json.append("\"").append(entry.getKey()).append("\":\"")
                    .append(entry.getValue()).append("\",");
        }
        if (!data.isEmpty()) {
            json.deleteCharAt(json.length() - 1);
        }
        json.append("}");

        sendResponse(exchange, code, json.toString());
    }

    private static void sendResponse(HttpExchange exchange, int code, String response) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");

        exchange.sendResponseHeaders(code, response.getBytes(StandardCharsets.UTF_8).length);
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes(StandardCharsets.UTF_8));
        os.close();
    }
}