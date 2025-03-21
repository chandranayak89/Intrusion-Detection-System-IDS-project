#!/usr/bin/env python3
"""
License Plate Recognition System
--------------------------------
This application detects and recognizes license plates in images and videos
using computer vision techniques and OCR.
"""

import cv2
import os
import argparse
import time
import json
from preprocessing import load_image, preprocess_image
from plate_detection import detect_plate, detect_plate_alternative
from ocr import enhance_and_recognize, recognize_multiple_plates
from video_processing import process_video, process_camera

def process_image(image_path, output_dir=None, show_result=True, save_result=True, save_plate=True):
    """
    Process a single image for license plate detection and recognition
    
    Args:
        image_path (str): Path to the input image
        output_dir (str): Directory to save output files
        show_result (bool): Whether to display the result
        save_result (bool): Whether to save the result image
        save_plate (bool): Whether to save the detected plate image
        
    Returns:
        str: Recognized license plate text
    """
    # Create output directory if it doesn't exist
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Load and preprocess the image
    img = load_image(image_path)
    original, edges = preprocess_image(img)
    
    # Detect license plate
    result_img, plate_img = detect_plate(original, edges)
    
    plate_text = None
    
    # If no plate detected, try alternative method
    if plate_img is None:
        print("No license plate detected with primary method, trying alternative...")
        alt_result, potential_plates = detect_plate_alternative(original)
        
        if potential_plates:
            plate_text = recognize_multiple_plates(potential_plates)
            result_img = alt_result
            
            # Save plate images if requested
            if save_plate and output_dir:
                for i, plate in enumerate(potential_plates):
                    plate_path = os.path.join(output_dir, f"plate_{i}.jpg")
                    cv2.imwrite(plate_path, plate)
    else:
        # Recognize text in the plate image
        plate_text = enhance_and_recognize(plate_img)
        
        # Save plate image if requested
        if save_plate and output_dir:
            plate_path = os.path.join(output_dir, "plate.jpg")
            cv2.imwrite(plate_path, plate_img)
    
    # Display the plate text on the result image
    if plate_text:
        cv2.putText(result_img, plate_text, (10, 30), 
                   cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
    else:
        plate_text = "No license plate detected"
        cv2.putText(result_img, plate_text, (10, 30), 
                   cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
    
    # Save result image if requested
    if save_result and output_dir:
        base_name = os.path.basename(image_path)
        result_path = os.path.join(output_dir, f"result_{base_name}")
        cv2.imwrite(result_path, result_img)
    
    # Display result if requested
    if show_result:
        cv2.imshow("License Plate Detection", result_img)
        cv2.waitKey(0)
        cv2.destroyAllWindows()
    
    return plate_text

def process_image_batch(image_dir, output_dir=None, show_results=False):
    """
    Process a batch of images for license plate detection and recognition
    
    Args:
        image_dir (str): Directory containing input images
        output_dir (str): Directory to save output files
        show_results (bool): Whether to display the results
        
    Returns:
        dict: Dictionary of recognized license plate texts for each image
    """
    # Create output directory if it doesn't exist
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Get list of image files
    image_extensions = ['.jpg', '.jpeg', '.png', '.bmp']
    image_files = [f for f in os.listdir(image_dir) if os.path.splitext(f.lower())[1] in image_extensions]
    
    if not image_files:
        print(f"No image files found in {image_dir}")
        return {}
    
    # Process each image
    results = {}
    for i, image_file in enumerate(image_files):
        print(f"Processing image {i+1}/{len(image_files)}: {image_file}")
        
        image_path = os.path.join(image_dir, image_file)
        
        # Create individual output directory for this image
        if output_dir:
            image_output_dir = os.path.join(output_dir, os.path.splitext(image_file)[0])
            if not os.path.exists(image_output_dir):
                os.makedirs(image_output_dir)
        else:
            image_output_dir = None
        
        # Process the image
        try:
            plate_text = process_image(image_path, image_output_dir, show_results, True, True)
            results[image_file] = plate_text
        except Exception as e:
            print(f"Error processing {image_file}: {e}")
            results[image_file] = f"Error: {str(e)}"
    
    # Save results to JSON file
    if output_dir:
        with open(os.path.join(output_dir, 'results.json'), 'w') as f:
            json.dump(results, f, indent=4)
    
    return results

def main():
    """Main function to parse arguments and run the appropriate processing function"""
    parser = argparse.ArgumentParser(description='License Plate Recognition System')
    
    # Create subparsers for different modes
    subparsers = parser.add_subparsers(dest='mode', help='Processing mode')
    
    # Image processing parser
    image_parser = subparsers.add_parser('image', help='Process a single image')
    image_parser.add_argument('input', help='Path to input image')
    image_parser.add_argument('--output-dir', help='Directory to save output files')
    image_parser.add_argument('--no-display', action='store_true', help='Do not display results')
    
    # Batch image processing parser
    batch_parser = subparsers.add_parser('batch', help='Process a batch of images')
    batch_parser.add_argument('input', help='Directory containing input images')
    batch_parser.add_argument('--output-dir', help='Directory to save output files')
    batch_parser.add_argument('--display', action='store_true', help='Display results for each image')
    
    # Video processing parser
    video_parser = subparsers.add_parser('video', help='Process a video file')
    video_parser.add_argument('input', help='Path to input video')
    video_parser.add_argument('--output', help='Path to save output video')
    video_parser.add_argument('--no-display', action='store_true', help='Do not display video while processing')
    video_parser.add_argument('--save-plates', action='store_true', help='Save detected license plates as images')
    
    # Camera processing parser
    camera_parser = subparsers.add_parser('camera', help='Process camera feed')
    camera_parser.add_argument('--camera-id', type=int, default=0, help='Camera device ID')
    camera_parser.add_argument('--save-plates', action='store_true', help='Save detected license plates as images')
    
    args = parser.parse_args()
    
    # Process arguments based on mode
    if args.mode == 'image':
        print(f"Processing image: {args.input}")
        plate_text = process_image(args.input, args.output_dir, not args.no_display)
        print(f"Detected license plate: {plate_text}")
    
    elif args.mode == 'batch':
        print(f"Processing images in directory: {args.input}")
        results = process_image_batch(args.input, args.output_dir, args.display)
        print("Processing complete. Results:")
        for image, text in results.items():
            print(f"{image}: {text}")
    
    elif args.mode == 'video':
        print(f"Processing video: {args.input}")
        plates = process_video(args.input, args.output, not args.no_display, args.save_plates)
        print("Detected license plates:")
        for plate in plates:
            print(f"Text: {plate['text']}, Time: {plate['timestamp']:.2f}s, Frame: {plate['frame']}")
    
    elif args.mode == 'camera':
        print(f"Processing camera feed from camera ID: {args.camera_id}")
        plates = process_camera(args.camera_id, True, args.save_plates)
        print("Detected license plates:")
        for plate in plates:
            time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(plate['timestamp']))
            print(f"Text: {plate['text']}, Time: {time_str}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 