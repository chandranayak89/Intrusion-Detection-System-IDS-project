"""
Deep Learning License Plate Detector using YOLO
-----------------------------------------------
This module provides functionality for detecting license plates
using a pre-trained YOLO model, which generally offers better
accuracy compared to traditional computer vision methods.

To use this module effectively, you'll need to:
1. Download a pre-trained YOLO model for license plate detection
2. Or train your own model using labeled license plate data
"""

import cv2
import numpy as np
import os
import time

class YOLOLicensePlateDetector:
    """YOLO-based license plate detector"""
    
    def __init__(self, config_path=None, weights_path=None, names_path=None, 
                 confidence_threshold=0.5, nms_threshold=0.4):
        """
        Initialize the YOLO license plate detector
        
        Args:
            config_path (str): Path to YOLOv4 config file
            weights_path (str): Path to YOLOv4 weights file
            names_path (str): Path to class names file
            confidence_threshold (float): Confidence threshold for detections
            nms_threshold (float): Non-maximum suppression threshold
        """
        self.confidence_threshold = confidence_threshold
        self.nms_threshold = nms_threshold
        
        # Load model if paths are provided
        if config_path and weights_path:
            self.load_model(config_path, weights_path)
        else:
            self.net = None
            print("YOLO model not loaded. Use load_model() to load a model.")
        
        # Load class names if provided
        if names_path:
            self.load_class_names(names_path)
        else:
            self.classes = ["license_plate"]
    
    def load_model(self, config_path, weights_path):
        """
        Load YOLO model from config and weights files
        
        Args:
            config_path (str): Path to YOLOv4 config file
            weights_path (str): Path to YOLOv4 weights file
        """
        try:
            self.net = cv2.dnn.readNetFromDarknet(config_path, weights_path)
            
            # Set preferred backend and target
            self.net.setPreferableBackend(cv2.dnn.DNN_BACKEND_OPENCV)
            self.net.setPreferableTarget(cv2.dnn.DNN_TARGET_CPU)
            
            # Get output layer names
            layer_names = self.net.getLayerNames()
            self.output_layers = [layer_names[i - 1] for i in self.net.getUnconnectedOutLayers()]
            
            print("YOLO model loaded successfully")
        except Exception as e:
            self.net = None
            print(f"Failed to load YOLO model: {e}")
    
    def load_class_names(self, names_path):
        """
        Load class names from a file
        
        Args:
            names_path (str): Path to class names file
        """
        try:
            with open(names_path, 'r') as f:
                self.classes = [line.strip() for line in f.readlines()]
            print(f"Loaded {len(self.classes)} class names")
        except Exception as e:
            self.classes = ["license_plate"]
            print(f"Failed to load class names: {e}")
    
    def detect(self, image):
        """
        Detect license plates in an image using YOLO
        
        Args:
            image (numpy.ndarray): Input image
            
        Returns:
            list: List of detected license plate bounding boxes [x, y, w, h, confidence]
        """
        if self.net is None:
            print("YOLO model not loaded. Use load_model() to load a model.")
            return []
        
        height, width, _ = image.shape
        
        # Prepare the image for YOLO input
        blob = cv2.dnn.blobFromImage(image, 1/255.0, (416, 416), swapRB=True, crop=False)
        self.net.setInput(blob)
        
        # Forward pass through the network
        outputs = self.net.forward(self.output_layers)
        
        # Process outputs
        boxes = []
        confidences = []
        class_ids = []
        
        for output in outputs:
            for detection in output:
                scores = detection[5:]
                class_id = np.argmax(scores)
                confidence = scores[class_id]
                
                if confidence > self.confidence_threshold:
                    # YOLO returns bounding box coordinates relative to the image size
                    center_x = int(detection[0] * width)
                    center_y = int(detection[1] * height)
                    box_width = int(detection[2] * width)
                    box_height = int(detection[3] * height)
                    
                    # Calculate top-left corner coordinates
                    x = int(center_x - (box_width / 2))
                    y = int(center_y - (box_height / 2))
                    
                    boxes.append([x, y, box_width, box_height])
                    confidences.append(float(confidence))
                    class_ids.append(class_id)
        
        # Apply non-maximum suppression to eliminate redundant overlapping boxes
        indices = cv2.dnn.NMSBoxes(boxes, confidences, self.confidence_threshold, self.nms_threshold)
        
        # Prepare results
        license_plates = []
        for i in indices:
            # Handle different OpenCV versions (older versions return a 2D array)
            i = i[0] if isinstance(i, (list, tuple, np.ndarray)) and len(i) == 1 else i
            
            box = boxes[i]
            confidence = confidences[i]
            class_id = class_ids[i]
            
            # Only keep license plate detections
            if self.classes[class_id] == "license_plate":
                license_plates.append(box + [confidence])
        
        return license_plates
    
    def draw_detections(self, image, detections):
        """
        Draw license plate detections on an image
        
        Args:
            image (numpy.ndarray): Input image
            detections (list): List of detected license plates [x, y, w, h, confidence]
            
        Returns:
            numpy.ndarray: Image with drawn detections
        """
        result_img = image.copy()
        
        for detection in detections:
            x, y, w, h, confidence = detection
            
            # Ensure coordinates are within image boundaries
            x, y = max(0, x), max(0, y)
            
            # Draw rectangle
            cv2.rectangle(result_img, (x, y), (x + w, y + h), (0, 255, 0), 2)
            
            # Draw confidence label
            label = f"License Plate: {confidence:.2f}"
            cv2.putText(result_img, label, (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)
        
        return result_img
    
    def extract_plates(self, image, detections):
        """
        Extract license plate regions from an image
        
        Args:
            image (numpy.ndarray): Input image
            detections (list): List of detected license plates [x, y, w, h, confidence]
            
        Returns:
            list: List of license plate images
        """
        plate_images = []
        
        for detection in detections:
            x, y, w, h, _ = detection
            
            # Ensure coordinates are within image boundaries
            x, y = max(0, x), max(0, y)
            w = min(w, image.shape[1] - x)
            h = min(h, image.shape[0] - y)
            
            # Extract plate region
            plate_img = image[y:y + h, x:x + w]
            plate_images.append(plate_img)
        
        return plate_images

def download_yolo_model():
    """
    Function to download a pre-trained YOLO model for license plate detection
    
    Note: This is a placeholder. You'll need to replace this with actual code
    to download specific model files or provide instructions to the user.
    """
    print("YOLO model download functionality not implemented.")
    print("Please download a pre-trained YOLO model for license plate detection from:")
    print("- https://github.com/ultralytics/yolov5")
    print("- Or other repositories with license plate detection models")
    print("\nAfter downloading, you can load the model with:")
    print("detector = YOLOLicensePlateDetector(config_path='path/to/config.cfg', weights_path='path/to/weights.weights')")

def train_yolo_model(data_path, config_path, output_path, epochs=100):
    """
    Function to train a YOLO model for license plate detection
    
    Note: This is a placeholder. You'll need to replace this with actual code
    to train a YOLO model using your preferred deep learning framework.
    
    Args:
        data_path (str): Path to training data
        config_path (str): Path to YOLO configuration file
        output_path (str): Path to save trained model
        epochs (int): Number of training epochs
    """
    print("YOLO model training functionality not implemented.")
    print("To train a YOLO model for license plate detection, consider using:")
    print("- Ultralytics YOLOv5/YOLOv8: https://github.com/ultralytics/yolov5")
    print("- Darknet: https://github.com/AlexeyAB/darknet")
    print("\nYou'll need labeled license plate data in the appropriate format.")

if __name__ == "__main__":
    # Example usage
    print("YOLO License Plate Detector Example")
    print("-----------------------------------")
    print("This module provides a framework for using YOLO for license plate detection.")
    print("To use it effectively, you need to:")
    print("1. Download or train a YOLO model for license plate detection")
    print("2. Load the model with the appropriate config and weights files")
    print("3. Use the detector to process images or video streams")
    
    # Example code (commented out since model files are not provided)
    """
    # Initialize detector with your model files
    detector = YOLOLicensePlateDetector(
        config_path="models/yolov4-license-plate.cfg",
        weights_path="models/yolov4-license-plate.weights",
        names_path="models/license-plate.names",
        confidence_threshold=0.5
    )
    
    # Load an image
    image_path = "sample_images/car.jpg"
    image = cv2.imread(image_path)
    
    if image is not None:
        # Detect license plates
        detections = detector.detect(image)
        
        # Draw detections
        result_img = detector.draw_detections(image, detections)
        
        # Extract plate images
        plate_images = detector.extract_plates(image, detections)
        
        # Display results
        cv2.imshow("Result", result_img)
        
        for i, plate_img in enumerate(plate_images):
            cv2.imshow(f"Plate {i+1}", plate_img)
        
        cv2.waitKey(0)
        cv2.destroyAllWindows()
    else:
        print(f"Failed to load image: {image_path}")
    """ 