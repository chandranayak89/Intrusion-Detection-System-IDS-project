import cv2
import time
import os
import traceback
from preprocessing import preprocess_image
from plate_detection import detect_plate, detect_plate_alternative
from ocr import enhance_and_recognize, recognize_multiple_plates

def process_video(video_path, output_path=None, display=True, save_plates=False):
    """
    Process a video file for license plate detection and recognition
    
    Args:
        video_path (str): Path to the video file
        output_path (str, optional): Path to save the processed video
        display (bool): Whether to display the processed video
        save_plates (bool): Whether to save detected license plates as images
        
    Returns:
        list: List of detected license plate texts with timestamps
    """
    # Verify the video file exists
    if not os.path.isfile(video_path):
        raise FileNotFoundError(f"Video file not found: {video_path}")
    
    # Check file extension
    _, ext = os.path.splitext(video_path)
    valid_extensions = ['.mp4', '.avi', '.mov', '.mkv', '.wmv']
    if ext.lower() not in valid_extensions:
        raise ValueError(f"Unsupported video format. Supported formats: {', '.join(valid_extensions)}")
    
    try:
        # Open the video file
        video = cv2.VideoCapture(video_path)
        
        if not video.isOpened():
            raise ValueError(f"Could not open video file {video_path}. The file may be corrupted or using an unsupported codec.")
        
        # Get video properties
        width = int(video.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(video.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = video.get(cv2.CAP_PROP_FPS)
        total_frames = int(video.get(cv2.CAP_PROP_FRAME_COUNT))
        
        print(f"Video properties: {width}x{height}, {fps} FPS, {total_frames} frames")
        
        # Create a video writer if output_path is provided
        if output_path:
            # Ensure output directory exists
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            fourcc = cv2.VideoWriter_fourcc(*'XVID')
            output_video = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
        
        # Initialize variables
        frame_count = 0
        detected_plates = []
        last_detection_time = 0
        min_detection_interval = 2.0  # Minimum seconds between plate detections
        
        # Process the video frame by frame
        while True:
            ret, frame = video.read()
            
            if not ret:
                break
            
            frame_count += 1
            current_time = frame_count / fps
            
            # Display progress periodically
            if frame_count % 30 == 0 or frame_count == 1:
                progress_percent = (frame_count / total_frames) * 100
                print(f"Processing: {progress_percent:.1f}% complete ({frame_count}/{total_frames} frames)")
            
            # Process frames at reduced rate to improve performance (e.g., every 5th frame)
            if frame_count % 5 == 0 or frame_count == 1:
                # Preprocess the frame
                _, edges = preprocess_image(frame)
                
                # Detect license plate
                result_frame, plate_img = detect_plate(frame, edges)
                
                # If no plate detected, try alternative method
                if plate_img is None:
                    result_frame, potential_plates = detect_plate_alternative(frame)
                    
                    # Process plates if found and enough time has passed since last detection
                    if potential_plates and (current_time - last_detection_time) >= min_detection_interval:
                        plate_text = recognize_multiple_plates(potential_plates)
                        
                        if plate_text and not plate_text.startswith("No"):
                            # Record the detection
                            detected_plates.append({
                                'text': plate_text,
                                'timestamp': current_time,
                                'frame': frame_count
                            })
                            last_detection_time = current_time
                            
                            # Display the plate text on the frame
                            cv2.putText(result_frame, plate_text, (10, 30), 
                                       cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
                            
                            # Save plate images if requested
                            if save_plates:
                                for i, plate in enumerate(potential_plates):
                                    plate_path = f"plate_{frame_count}_{i}.jpg"
                                    cv2.imwrite(plate_path, plate)
                else:
                    # Process plate if enough time has passed since last detection
                    if (current_time - last_detection_time) >= min_detection_interval:
                        plate_text = enhance_and_recognize(plate_img)
                        
                        if plate_text and not plate_text.startswith("No") and not plate_text.startswith("Invalid"):
                            # Record the detection
                            detected_plates.append({
                                'text': plate_text,
                                'timestamp': current_time,
                                'frame': frame_count
                            })
                            last_detection_time = current_time
                            
                            # Display the plate text on the frame
                            cv2.putText(result_frame, plate_text, (10, 30), 
                                       cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
                            
                            # Save plate image if requested
                            if save_plates:
                                plate_path = f"plate_{frame_count}.jpg"
                                cv2.imwrite(plate_path, plate_img)
            else:
                result_frame = frame
                
                # Display the most recent plate text if available
                if detected_plates:
                    most_recent = detected_plates[-1]['text']
                    cv2.putText(result_frame, most_recent, (10, 30), 
                               cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
            
            # Display progress information
            progress_percent = (frame_count / total_frames) * 100
            cv2.putText(result_frame, f"Progress: {progress_percent:.1f}%", (10, height - 10), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 1)
            
            # Display frame if requested
            if display:
                cv2.imshow("License Plate Detection", result_frame)
                
                # Break the loop if 'q' is pressed
                key = cv2.waitKey(1) & 0xFF
                if key == ord('q'):
                    print("Processing stopped by user.")
                    break
            
            # Write frame to output video if path is provided
            if output_path:
                output_video.write(result_frame)
        
        # Release resources
        video.release()
        
        if output_path:
            output_video.release()
        
        if display:
            cv2.destroyAllWindows()
        
        print(f"Processing complete: {frame_count} frames processed, {len(detected_plates)} plates detected.")
        return detected_plates
    
    except Exception as e:
        print(f"Error during video processing: {e}")
        print(traceback.format_exc())
        cv2.destroyAllWindows()
        return []

def process_camera(camera_id=0, display=True, save_plates=False, frame_skip=5, resolution_scale=0.5, preview_mode=False):
    """
    Process a camera feed for license plate detection and recognition
    
    Args:
        camera_id (int): Camera device ID
        display (bool): Whether to display the processed video
        save_plates (bool): Whether to save detected license plates as images
        frame_skip (int): Number of frames to skip between processing (higher = faster but less accurate)
        resolution_scale (float): Scale factor for resolution (lower = faster)
        preview_mode (bool): If True, only show camera feed with minimal processing
    """
    # Open the camera
    video = cv2.VideoCapture(camera_id)
    
    if not video.isOpened():
        raise ValueError(f"Could not open camera with ID {camera_id}")
    
    # Initialize variables
    detected_plates = []
    last_detection_time = 0
    min_detection_interval = 2.0  # Minimum seconds between plate detections
    frame_count = 0
    processing_fps = 0
    fps_update_time = time.time()
    fps_frame_count = 0
    key_pressed = None
    last_key_time = 0
    key_display_duration = 1.0  # Display key press for 1 second
    
    # Process the camera feed frame by frame
    print("Processing camera feed. Press 'q' to quit, 'p' to toggle preview mode.")
    print(f"Current settings: frame_skip={frame_skip}, resolution_scale={resolution_scale}")
    
    try:
        while True:
            start_time = time.time()
            ret, frame = video.read()
            
            if not ret:
                print("Failed to capture frame from camera")
                break
            
            current_time = time.time()
            frame_count += 1
            fps_frame_count += 1
            
            # Calculate and update FPS every second
            if current_time - fps_update_time >= 1.0:
                processing_fps = fps_frame_count / (current_time - fps_update_time)
                fps_update_time = current_time
                fps_frame_count = 0
            
            # Create a copy of the original frame for display
            display_frame = frame.copy()
            
            # Scale down resolution to improve performance if needed
            if resolution_scale < 1.0:
                frame_height, frame_width = frame.shape[:2]
                new_width = int(frame_width * resolution_scale)
                new_height = int(frame_height * resolution_scale)
                processing_frame = cv2.resize(frame, (new_width, new_height))
            else:
                processing_frame = frame
            
            # Process only selected frames to improve performance
            process_this_frame = frame_count % frame_skip == 0
            
            if process_this_frame and not preview_mode:
                # Preprocess the frame
                _, edges = preprocess_image(processing_frame)
                
                # Detect license plate
                result_frame, plate_img = detect_plate(processing_frame, edges)
                
                # If no plate detected, try alternative method
                if plate_img is None:
                    result_frame, potential_plates = detect_plate_alternative(processing_frame)
                    
                    # Process plates if found and enough time has passed since last detection
                    if potential_plates and (current_time - last_detection_time) >= min_detection_interval:
                        plate_text = recognize_multiple_plates(potential_plates)
                        
                        if plate_text and not plate_text.startswith("No"):
                            # Record the detection
                            detected_plates.append({
                                'text': plate_text,
                                'timestamp': current_time
                            })
                            last_detection_time = current_time
                            
                            # Display the plate text on the frame
                            cv2.putText(display_frame, plate_text, (10, 30), 
                                       cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
                            
                            # Save plate images if requested
                            if save_plates:
                                timestamp = int(current_time)
                                for i, plate in enumerate(potential_plates):
                                    plate_path = f"plate_{timestamp}_{i}.jpg"
                                    cv2.imwrite(plate_path, plate)
                else:
                    # Process plate if enough time has passed since last detection
                    if (current_time - last_detection_time) >= min_detection_interval:
                        plate_text = enhance_and_recognize(plate_img)
                        
                        if plate_text and not plate_text.startswith("No") and not plate_text.startswith("Invalid"):
                            # Record the detection
                            detected_plates.append({
                                'text': plate_text,
                                'timestamp': current_time
                            })
                            last_detection_time = current_time
                            
                            # Display the plate text on the frame
                            cv2.putText(display_frame, plate_text, (10, 30), 
                                       cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
                            
                            # Save plate image if requested
                            if save_plates:
                                timestamp = int(current_time)
                                plate_path = f"plate_{timestamp}.jpg"
                                cv2.imwrite(plate_path, plate_img)
            
            # Always display the most recent plate text if available
            elif detected_plates and not preview_mode:
                most_recent = detected_plates[-1]['text']
                cv2.putText(display_frame, most_recent, (10, 30), 
                           cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
            
            # Calculate frame processing time
            frame_time = time.time() - start_time
            
            # Get frame dimensions for positioning text
            height, width = display_frame.shape[:2]
            
            # Create a semi-transparent overlay for controls at the bottom
            overlay = display_frame.copy()
            cv2.rectangle(overlay, (0, height-130), (width, height), (0, 0, 0), -1)
            cv2.addWeighted(overlay, 0.6, display_frame, 0.4, 0, display_frame)
            
            # Display mode and performance information
            mode_text = "PREVIEW MODE" if preview_mode else "PROCESSING MODE"
            cv2.putText(display_frame, f"{mode_text}", 
                       (10, height-100), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
            
            cv2.putText(display_frame, f"FPS: {processing_fps:.1f}", 
                       (10, height-70), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
            
            cv2.putText(display_frame, f"Frame Skip: {frame_skip}", 
                       (width//2, height-100), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
            
            cv2.putText(display_frame, f"Resolution Scale: {resolution_scale:.2f}", 
                       (width//2, height-70), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
            
            # Display controls
            controls_text = "Controls: [P]review mode | [+/-] Frame skip | [Q]uit"
            cv2.putText(display_frame, controls_text, 
                       (10, height-30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
            
            # Display recently detected key press
            if key_pressed and (current_time - last_key_time) < key_display_duration:
                key_text = f"KEY PRESSED: {key_pressed}"
                cv2.putText(display_frame, key_text, 
                           (width//2 - 100, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 255, 255), 2)
            
            # Display frame if requested
            if display:
                cv2.imshow("License Plate Detection", display_frame)
                
                # Check for key presses - using a longer wait time to ensure key presses are detected
                key = cv2.waitKey(5) & 0xFF
                
                # Process key presses
                if key != 255:  # 255 means no key was pressed
                    # Break the loop if 'q' is pressed
                    if key == ord('q'):
                        print("Quitting - 'q' key pressed")
                        break
                    
                    # Toggle preview mode if 'p' is pressed
                    elif key == ord('p'):
                        preview_mode = not preview_mode
                        key_pressed = "P - Preview: " + ("ON" if preview_mode else "OFF")
                        last_key_time = current_time
                        print(f"Preview mode: {'ON' if preview_mode else 'OFF'}")
                    
                    # Increase frame skip if '+' is pressed
                    elif key == ord('+') or key == ord('='):
                        frame_skip += 1
                        key_pressed = "+ - Frame Skip: " + str(frame_skip)
                        last_key_time = current_time
                        print(f"Frame skip increased to {frame_skip}")
                    
                    # Decrease frame skip if '-' is pressed
                    elif key == ord('-') or key == ord('_'):
                        if frame_skip > 1:
                            frame_skip -= 1
                            key_pressed = "- - Frame Skip: " + str(frame_skip)
                            last_key_time = current_time
                            print(f"Frame skip decreased to {frame_skip}")
    
    except KeyboardInterrupt:
        print("Processing stopped by user")
    except Exception as e:
        print(f"Error during camera processing: {e}")
        print(traceback.format_exc())
    finally:
        # Release resources
        video.release()
        
        if display:
            cv2.destroyAllWindows()
        
        return detected_plates

if __name__ == "__main__":
    # Test the video processing functions
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "camera":
            # Process camera feed
            camera_id = 0 if len(sys.argv) <= 2 else int(sys.argv[2])
            plates = process_camera(camera_id=camera_id)
            print("Detected plates:", plates)
        else:
            # Process video file
            video_path = sys.argv[1]
            output_path = sys.argv[2] if len(sys.argv) > 2 else None
            
            try:
                plates = process_video(video_path, output_path)
                print("Detected plates:")
                for plate in plates:
                    print(f"Text: {plate['text']}, Time: {plate['timestamp']:.2f}s, Frame: {plate['frame']}")
            except Exception as e:
                print(f"Error: {e}")
                print(traceback.format_exc())
    else:
        print("Please provide a video path or 'camera' as a command line argument.") 