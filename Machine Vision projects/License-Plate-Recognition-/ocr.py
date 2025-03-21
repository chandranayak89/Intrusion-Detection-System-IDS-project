import cv2
import pytesseract
import re
import os
import platform

# Set Tesseract path for Windows
if platform.system() == "Windows":
    if os.path.exists(r"C:\Program Files\Tesseract-OCR\tesseract.exe"):
        pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    else:
        print("Warning: Tesseract OCR not found at default location. Please make sure Tesseract is installed.")

def recognize_plate(plate_img):
    """
    Apply OCR to extract text from a license plate image
    
    Args:
        plate_img (numpy.ndarray): License plate image
        
    Returns:
        str: Recognized license plate text
    """
    if plate_img is None:
        return "No plate image provided"
    
    # Convert to grayscale if needed
    gray = cv2.cvtColor(plate_img, cv2.COLOR_BGR2GRAY) if len(plate_img.shape) == 3 else plate_img
    
    # Apply thresholding
    _, binary = cv2.threshold(gray, 100, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    
    # Increase the size of the image for better OCR results
    resized = cv2.resize(binary, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
    
    # Apply OCR using Tesseract
    # PSM 7 - Treat the image as a single text line
    # PSM 8 - Treat the image as a single word
    # PSM 13 - Treat the image as a single line of text, but no specific script
    config = r'--oem 3 --psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    plate_text = pytesseract.image_to_string(resized, config=config)
    
    # Clean the text
    plate_text = clean_plate_text(plate_text)
    
    return plate_text

def clean_plate_text(text):
    """
    Clean the recognized text by removing non-alphanumeric characters
    
    Args:
        text (str): Raw OCR text
        
    Returns:
        str: Cleaned license plate text
    """
    # Remove any non-alphanumeric characters
    cleaned_text = re.sub(r'[^A-Z0-9]', '', text.upper())
    
    # Validate the resulting text length
    # Common license plate formats are between 5-8 characters
    if len(cleaned_text) < 4 or len(cleaned_text) > 10:
        return "Invalid plate text: " + cleaned_text
    
    return cleaned_text

def recognize_multiple_plates(plate_images):
    """
    Apply OCR to multiple license plate images and return the best result
    
    Args:
        plate_images (list): List of license plate images
        
    Returns:
        str: Best recognized license plate text
    """
    results = []
    
    for plate in plate_images:
        text = recognize_plate(plate)
        if text and text.startswith("Invalid") is False:
            results.append(text)
    
    # Return the most likely license plate text
    # This could be improved with a confidence score from Tesseract
    if results:
        # For now, we'll just return the first valid result
        return results[0]
    else:
        return "No valid license plate detected"

def enhance_and_recognize(plate_img):
    """
    Apply various enhancements and recognize the plate with the best result
    
    Args:
        plate_img (numpy.ndarray): License plate image
        
    Returns:
        str: Best recognized license plate text
    """
    if plate_img is None:
        return "No plate image provided"
    
    results = []
    
    # Original plate image
    results.append(recognize_plate(plate_img))
    
    # Convert to grayscale
    gray = cv2.cvtColor(plate_img, cv2.COLOR_BGR2GRAY) if len(plate_img.shape) == 3 else plate_img
    
    # Try different preprocessing approaches
    # 1. Bilateral filter
    bilateral = cv2.bilateralFilter(gray, 11, 17, 17)
    results.append(recognize_plate(bilateral))
    
    # 2. Adaptive thresholding
    thresh = cv2.adaptiveThreshold(bilateral, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                                   cv2.THRESH_BINARY, 11, 2)
    results.append(recognize_plate(thresh))
    
    # 3. Blur and threshold
    blur = cv2.GaussianBlur(gray, (5, 5), 0)
    _, otsu = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    results.append(recognize_plate(otsu))
    
    # Filter out invalid results
    valid_results = [text for text in results if text and not text.startswith("Invalid") and not text.startswith("No")]
    
    if valid_results:
        # Return the most common result or the first one
        from collections import Counter
        count = Counter(valid_results)
        return count.most_common(1)[0][0]
    else:
        return "No valid license plate detected"

if __name__ == "__main__":
    # Test the OCR functions
    import sys
    from preprocessing import load_image
    from plate_detection import detect_plate, detect_plate_alternative, preprocess_image
    
    if len(sys.argv) > 1:
        image_path = sys.argv[1]
        try:
            img = load_image(image_path)
            original, edges = preprocess_image(img)
            
            result_img, plate_img = detect_plate(original, edges)
            
            if plate_img is not None:
                plate_text = enhance_and_recognize(plate_img)
                print("Detected License Plate:", plate_text)
            else:
                print("No license plate detected with primary method, trying alternative...")
                alt_result, potential_plates = detect_plate_alternative(original)
                
                if potential_plates:
                    plate_text = recognize_multiple_plates(potential_plates)
                    print("Detected License Plate (alternative method):", plate_text)
                else:
                    print("No license plates detected.")
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("Please provide an image path as a command line argument.") 