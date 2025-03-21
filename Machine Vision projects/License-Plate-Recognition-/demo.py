#!/usr/bin/env python3
"""
License Plate Recognition System Demo
------------------------------------
This script demonstrates the usage of the LPR system with sample images and a video.
"""

import os
import sys
import cv2
import traceback
from preprocessing import load_image, preprocess_image
from plate_detection import detect_plate, detect_plate_alternative
from ocr import enhance_and_recognize, recognize_multiple_plates
from video_processing import process_video, process_camera

def demo_single_image(image_path):
    """
    Demonstrate license plate recognition on a single image
    
    Args:
        image_path (str): Path to the input image
    """
    print(f"\nProcessing image: {image_path}")
    
    try:
        # Load and preprocess the image
        img = load_image(image_path)
        original, edges = preprocess_image(img)
        
        # Display preprocessing results
        cv2.imshow("Original", original)
        cv2.imshow("Edges", edges)
        print("Displaying preprocessing results. Press any key to continue...")
        cv2.waitKey(0)
        
        # Detect license plate
        result_img, plate_img = detect_plate(original, edges)
        
        if plate_img is None:
            print("No license plate detected with primary method, trying alternative...")
            alt_result, potential_plates = detect_plate_alternative(original)
            
            if potential_plates:
                # Display alternative detection results
                cv2.imshow("Alternative Detection", alt_result)
                
                for i, plate in enumerate(potential_plates):
                    cv2.imshow(f"Potential Plate {i+1}", plate)
                
                # Recognize text in potential plates
                plate_text = recognize_multiple_plates(potential_plates)
                print(f"Detected License Plate (alternative method): {plate_text}")
                
                # Display the plate text on the result image
                cv2.putText(alt_result, plate_text, (10, 30), 
                           cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
                cv2.imshow("Result", alt_result)
            else:
                print("No license plates detected.")
        else:
            # Display detection results
            cv2.imshow("Detection", result_img)
            cv2.imshow("Plate", plate_img)
            
            # Enhance and recognize text in the plate image
            plate_text = enhance_and_recognize(plate_img)
            print(f"Detected License Plate: {plate_text}")
            
            # Display the plate text on the result image
            cv2.putText(result_img, plate_text, (10, 30), 
                       cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
            cv2.imshow("Result", result_img)
        
        print("Displaying results. Press any key to continue...")
        cv2.waitKey(0)
        cv2.destroyAllWindows()
    
    except Exception as e:
        print(f"Error processing image: {e}")
        print(traceback.format_exc())
        cv2.destroyAllWindows()

def demo_video(video_path):
    """
    Demonstrate license plate recognition on a video
    
    Args:
        video_path (str): Path to the input video
    """
    print(f"\nProcessing video: {video_path}")
    
    # Check if the file exists and has a valid video extension
    if not os.path.isfile(video_path):
        print(f"Error: Video file not found: {video_path}")
        return
    
    # Check if file has a valid video extension
    _, ext = os.path.splitext(video_path)
    valid_extensions = ['.mp4', '.avi', '.mov', '.mkv', '.wmv']
    if ext.lower() not in valid_extensions:
        print(f"Error: File doesn't have a valid video extension. Supported formats: {', '.join(valid_extensions)}")
        return
    
    try:
        # Process the video
        plates = process_video(video_path, display=True)
        
        # Display results
        print("Detected license plates:")
        for plate in plates:
            print(f"Text: {plate['text']}, Time: {plate['timestamp']:.2f}s, Frame: {plate['frame']}")
    
    except Exception as e:
        print(f"Error processing video: {e}")
        print(traceback.format_exc())

def demo_camera():
    """
    Demonstrate license plate recognition using a camera
    """
    print("\nProcessing camera feed. Select performance options:")
    
    try:
        # Get performance options from user
        print("\nPerformance Options")
        print("===================")
        
        # Ask for frame skip option
        frame_skip = input("Enter frame skip value (higher = faster but less accurate, recommended: 3-10) [5]: ")
        frame_skip = int(frame_skip) if frame_skip.strip() else 5
        
        # Ask for resolution scale
        resolution_scale = input("Enter resolution scale (lower = faster, 0.5 = half size, recommended: 0.3-0.8) [0.5]: ")
        resolution_scale = float(resolution_scale) if resolution_scale.strip() else 0.5
        
        # Ask for preview mode
        preview_mode = input("Start in preview mode for maximum speed? (y/n) [n]: ").lower().startswith('y')
        
        print("\nControls:")
        print("- Press 'q' to quit")
        print("- Press 'p' to toggle preview mode")
        print("- Press '+'/'-' to increase/decrease frame skip")
        print("\nStarting camera feed...")
        
        # Process the camera feed with optimized parameters
        plates = process_camera(
            camera_id=0, 
            display=True, 
            frame_skip=frame_skip,
            resolution_scale=resolution_scale,
            preview_mode=preview_mode
        )
        
        # Display results
        print("Detected license plates:")
        for plate in plates:
            print(f"Text: {plate['text']}, Time: {plate['timestamp']}")
    
    except Exception as e:
        print(f"Error accessing camera: {e}")
        print(traceback.format_exc())

def print_demo_menu():
    """Print the demo menu options"""
    print("\nLicense Plate Recognition System Demo")
    print("=====================================")
    print("1. Process a sample image")
    print("2. Process a video file")
    print("3. Process camera feed")
    print("4. Exit")
    return input("Enter your choice (1-4): ")

def main():
    """Main demo function"""
    # Create sample_images directory if it doesn't exist
    if not os.path.exists("sample_images"):
        os.makedirs("sample_images")
    
    # Check if there are sample images
    sample_images = [f for f in os.listdir("sample_images") 
                    if f.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp'))]
    
    if not sample_images:
        print("No sample images found in the 'sample_images' directory.")
        print("Please add some images to the 'sample_images' directory to use the demo.")
    
    while True:
        choice = print_demo_menu()
        
        if choice == '1':
            # Process a sample image
            if sample_images:
                # Display available sample images
                print("\nAvailable sample images:")
                for i, img in enumerate(sample_images):
                    print(f"{i+1}. {img}")
                
                img_choice = input("\nEnter the number of the image to process (or just press Enter for the first one): ")
                
                try:
                    if img_choice.strip():
                        idx = int(img_choice) - 1
                        if 0 <= idx < len(sample_images):
                            image_path = os.path.join("sample_images", sample_images[idx])
                        else:
                            print(f"Invalid selection. Using the first image.")
                            image_path = os.path.join("sample_images", sample_images[0])
                    else:
                        image_path = os.path.join("sample_images", sample_images[0])
                    
                    print(f"Using sample image: {image_path}")
                    demo_single_image(image_path)
                except ValueError:
                    print("Invalid input. Using the first image.")
                    image_path = os.path.join("sample_images", sample_images[0])
                    print(f"Using sample image: {image_path}")
                    demo_single_image(image_path)
            else:
                image_path = input("Enter the full path to an image file (including extension): ")
                if os.path.exists(image_path) and os.path.isfile(image_path):
                    demo_single_image(image_path)
                else:
                    print(f"File not found: {image_path}")
        
        elif choice == '2':
            # Process a video file
            video_path = input("Enter the full path to a video file (including extension like .mp4): ")
            if os.path.exists(video_path) and os.path.isfile(video_path):
                demo_video(video_path)
            else:
                print(f"File not found: {video_path}")
        
        elif choice == '3':
            # Process camera feed
            demo_camera()
        
        elif choice == '4':
            # Exit
            print("Exiting demo.")
            break
        
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    main() 