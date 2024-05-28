package com.example.OAuth2.s3.controller;

import com.amazonaws.Response;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.example.OAuth2.YamlPropertySourceFactory;
import com.example.OAuth2.s3.service.FileUploadService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/upload")
@RequiredArgsConstructor
@PropertySource(value="classpath:application-aws.yml",factory= YamlPropertySourceFactory.class)
public class FileUploadController {
    private final AmazonS3Client amazonS3Client;
    private final FileUploadService fileUploadService;

    @Value("${cloud.aws.s3.bucket}")
    private String bucket;

    @PostMapping
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) {
        return fileUploadService.uploadS3(file);
    }

    @PostMapping("/social")
    public ResponseEntity<String> uploadSocialImage(@RequestParam("email") String email, @RequestParam("url") String url) throws IOException {
        return fileUploadService.uploadS3Social(email, url);
    }
}