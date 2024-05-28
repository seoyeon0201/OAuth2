package com.example.OAuth2.s3.service;

import com.amazonaws.Response;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.example.OAuth2.YamlPropertySourceFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

@Slf4j
@Service
@RequiredArgsConstructor
@PropertySource(value="classpath:application-aws.yml",factory= YamlPropertySourceFactory.class)
public class FileUploadService {
    private final AmazonS3Client amazonS3Client;

    @Value("${cloud.aws.s3.bucket}")
    private String bucket;

    public ResponseEntity<String> uploadS3(MultipartFile file) {
        try {
            String fileName = file.getOriginalFilename();
            String fileUrl = "https://"+bucket+"/test"+fileName;
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentType(file.getContentType());
            metadata.setContentLength(file.getSize());

            amazonS3Client.putObject(bucket, fileName, file.getInputStream(), metadata);

            return ResponseEntity.ok(fileUrl);
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    public ResponseEntity<String> uploadS3Social(String email, String socialUrl) throws IOException {

        InputStream inputStream = null;
        ByteArrayOutputStream byteArrayOutputStream = null;

        try {
            //URL open해 이미지 다운로드 후 S3에 업로드
            URL url = new URL(socialUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            inputStream = connection.getInputStream();

            //InputStream을 ByteArrayOutputStream에 저장
            byteArrayOutputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int length;
            while ((length = inputStream.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, length);
            }
            //byte 배열로 변환
            byte[] fileBytes = byteArrayOutputStream.toByteArray();
            long contentLength = fileBytes.length;

            InputStream uploadInputStream = new ByteArrayInputStream(fileBytes);

            String fileName = email;
            String fileUrl = "https//" + email;
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentType(connection.getContentType());
            metadata.setContentLength(contentLength);

            amazonS3Client.putObject(bucket, fileName, uploadInputStream, metadata);

            return ResponseEntity.ok(fileUrl);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
