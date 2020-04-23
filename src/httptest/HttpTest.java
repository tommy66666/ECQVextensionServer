package httptest;

import Httputil.HttpMethod;
import JsonMethod.JsonStr;
import Person.personbean;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

//import javafx.application.Application;
//import javafx.stage.Stage;
//import javafx.scene.Scene;
import javafx.scene.layout.BorderPane;

import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;

//http

//import javafx.io.http.*;    
//import javafx.ext.swing.SwingButton;  
//import java.io.DataInputStream;  
//import javafx.scene.layout.HBox;  
//import javafx.ext.swing.SwingTextField;  

/**
 *
 * @author Legend-novo
 */
public class HttpTest extends Application {
    private String message = null;
    /**
     * ������ת����JSON��������
     * @return ����JSON��������
     */
    public String setJson(){
        personbean person1 = new personbean("zhangsan",21);
        //personbean person2 = new personbean("lisi",25);
        //personbean person3 = new personbean("tom",31);
        final List<personbean> list = new ArrayList<>();
        list.add(person1);
        //list.add(person2);
        //list.add(person3);
        //
        //return "tommy";
        //
        return JsonStr.getJson(list);
    }
    
    


    @Override
	public void start(Stage primaryStage) {
    try {
        // Read file fxml and draw interface.
        Parent root = FXMLLoader.load(getClass()
                .getResource("/application/sample.fxml"));

        primaryStage.setTitle("My Application");
        primaryStage.setScene(new Scene(root));
        primaryStage.show();

    } catch(Exception e) {
        e.printStackTrace();
    }
    }

	public static void main(String[] args) {
    launch(args);
	}
    
    
    
    
    
    
    /**
     * ��GET�ķ�ʽ�������ݽ���
     * @param primaryStage 
     */
    /*
    public void GETHttp(Stage primaryStage){

        final HashMap<String,String> map = new HashMap<>();
         map.put("data",setJson());
         System.out.println(setJson());
        
        final Label labelget = new Label();
        final Label labelsend = new Label();
        Button btnget = new Button();
        btnget.setText("��ȡ��Ϣ");
        Button btnsend = new Button();
        btnsend.setText("������Ϣ");
        btnget.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                System.out.println("�����btnget��");
                try {
                    message = HttpMethod.getGETString();
                    labelget.setText(message);
                } catch (Exception ex) {
                    Logger.getLogger(HttpTest.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
        
         btnsend.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                System.out.println("�����btnsend��");
                try {
                	//****
                    if(HttpMethod.sendGETString(map, "UTF-8")){
                        labelsend.setText("sending successed");
                    }else{
                        labelsend.setText("sending failed");
                    }//*****
                    message = HttpMethod.sendGETString(map, "UTF-8");
                	labelsend.setText(message);
                } catch (Exception ex) {
                    Logger.getLogger(HttpTest.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
        VBox vb = new VBox(10);
        vb.getChildren().addAll(btnget,labelget,btnsend,labelsend);
        StackPane root = new StackPane();
        root.getChildren().add(vb);
        
        Scene scene = new Scene(root, 300, 250);
        
        primaryStage.setTitle("GET��ʽ���ݽ���");
        primaryStage.setScene(scene);
    }
    
     public void POSTHttp(Stage primaryStage){

        final HashMap<String,String> map = new HashMap<>();
         map.put("data",setJson());
         System.out.println(setJson());
        
        final Label labelget = new Label();
        final Label labelsend = new Label();
        Button btnget = new Button();
        btnget.setText("��ȡ��Ϣ");
        Button btnsend = new Button();
        btnsend.setText("������Ϣ");
        btnget.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                System.out.println("�����btnget��");
                try {
                    message = HttpMethod.getPOSTString();
                    labelget.setText(message);
                } catch (Exception ex) {
                    Logger.getLogger(HttpTest.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
        
         btnsend.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                System.out.println("�����btnsend��");
                try {
                	//****
                    if(HttpMethod.sendGETString(map, "UTF-8")){
                        labelsend.setText("sending successed");
                    }else{
                        labelsend.setText("sending failed");
                    }//****
                	message = HttpMethod.sendGETString(map, "UTF-8");
                	labelsend.setText(message);
                } catch (Exception ex) {
                    Logger.getLogger(HttpTest.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
        VBox vb = new VBox(10);
        vb.getChildren().addAll(btnget,labelget,btnsend,labelsend);
        StackPane root = new StackPane();
        root.getChildren().add(vb);
        
        Scene scene = new Scene(root, 300, 250);
        
        primaryStage.setTitle("POST��ʽ���ݽ���");
        primaryStage.setScene(scene);
    }
    
    @Override
    public void start(Stage primaryStage) {
//        POSTHttp(primaryStage);
        GETHttp(primaryStage);
        primaryStage.show();
        
    }
    

public static void main(String[] args) {
        launch(args);
    }
    
    */



}