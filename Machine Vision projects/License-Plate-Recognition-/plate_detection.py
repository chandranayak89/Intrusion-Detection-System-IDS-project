import cv2
import numpy as np
import imutils

def find_plate_contour(processed_img):
    """
    Find license plate contours in the processed edge image
    
    Args:
        processed_img (numpy.ndarray): Processed edge image
        
    Returns:
        numpy.ndarray: License plate contour or None if not found
    """
    # Find contours in the edge image
    contours, _ = cv2.findContours(processed_img, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
    
    # Sort contours by area, largest first
    contours = sorted(contours, key=cv2.contourArea, reverse=True)[:10]
    
    # Loop through contours and find the license plate
    for contour in contours:
        perimeter = cv2.arcLength(contour, True)
        approx = cv2.approxPolyDP(contour, 0.02 * perimeter, True)
        
        # Look for rectangular contours with 4 corners
        if len(approx) == 4:
            return approx
    
    return None

def extract_plate(original_img, plate_contour):
    """
    Extract the license plate from the original image using the contour
    
    Args:
        original_img (numpy.ndarray): Original image
        plate_contour (numpy.ndarray): License plate contour
        
    Returns:
        numpy.ndarray: Cropped license plate image
    """
    if plate_contour is None:
        return None
    
    # Get bounding rectangle
    x, y, w, h = cv2.boundingRect(plate_contour)
    
    # Crop the license plate region
    plate_img = original_img[y:y + h, x:x + w]
    
    return plate_img

def detect_plate(img, edges):
    """
    Detect license plate in an image
    
    Args:
        img (numpy.ndarray): Original image
        edges (numpy.ndarray): Processed edge image
        
    Returns:
        tuple: Result image with marked plate and cropped plate image
    """
    result_img = img.copy()
    
    # Find license plate contour
    plate_contour = find_plate_contour(edges)
    
    if plate_contour is not None:
        # Draw contour on the result image
        cv2.drawContours(result_img, [plate_contour], -1, (0, 255, 0), 3)
        
        # Extract plate image
        plate_img = extract_plate(img, plate_contour)
        
        return result_img, plate_img
    
    return result_img, None

def detect_plate_alternative(img):
    """
    Alternative method for license plate detection using aspect ratio filtering
    Used as a fallback when contour detection fails
    
    Args:
        img (numpy.ndarray): Original image
        
    Returns:
        tuple: Result image with marked plates and list of potential plate images
    """
    result_img = img.copy()
    potential_plates = []
    
    # Convert to grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    
    # Apply bilateral filter to reduce noise while keeping edges sharp
    bfilter = cv2.bilateralFilter(gray, 11, 17, 17)
    
    # Edge detection
    edged = cv2.Canny(bfilter, 30, 200)
    
    # Find contours
    cnts = cv2.findContours(edged.copy(), cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
    cnts = imutils.grab_contours(cnts)
    cnts = sorted(cnts, key=cv2.contourArea, reverse=True)[:10]
    
    for c in cnts:
        # Approximate the contour
        peri = cv2.arcLength(c, True)
        approx = cv2.approxPolyDP(c, 0.018 * peri, True)
        
        # Get rectangle coordinates and dimensions
        x, y, w, h = cv2.boundingRect(approx)
        
        # Check for appropriate aspect ratio (license plates are typically wider than tall)
        aspect_ratio = w / float(h)
        
        if 2.0 < aspect_ratio < 6.0 and w > 100 and h > 20:
            # Draw rectangle
            cv2.rectangle(result_img, (x, y), (x + w, y + h), (0, 255, 0), 3)
            
            # Crop potential plate
            potential_plate = img[y:y + h, x:x + w]
            potential_plates.append(potential_plate)
    
    return result_img, potential_plates

if __name__ == "__main__":
    # Test the plate detection functions
    import sys
    from preprocessing import load_image, preprocess_image
    
    if len(sys.argv) > 1:
        image_path = sys.argv[1]
        try:
            img = load_image(image_path)
            original, edges = preprocess_image(img)
            
            result_img, plate_img = detect_plate(original, edges)
            
            # Display results
            cv2.imshow("Result", result_img)
            
            if plate_img is not None:
                cv2.imshow("Plate", plate_img)
            else:
                print("No license plate detected with primary method, trying alternative...")
                alt_result, potential_plates = detect_plate_alternative(original)
                cv2.imshow("Alternative Result", alt_result)
                
                for i, plate in enumerate(potential_plates):
                    cv2.imshow(f"Potential Plate {i+1}", plate)
            
            cv2.waitKey(0)
            cv2.destroyAllWindows()
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("Please provide an image path as a command line argument.") 