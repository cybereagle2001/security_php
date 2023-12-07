<?php

// Include the VirusTotal class
require_once('./virustotal/virustotal.class.php');

// VirusTotal API key
$apikey = 'f0d12dff20c93293818a2ac6574d05825c5c44ce6d3178fb3ee1bc2fc0090169';

// Function to check file with VirusTotal
function checkFileWithVirusTotal($filename)
{
    global $apikey;

    // Initialize VirusTotal API
    $vt = new virustotal($apikey);

    // Check the file with VirusTotal
    $res = $vt->checkFile($filename);

    // Process the result
    switch ($res) {
        case -99:
            // API limit exceeded
            // Deal with it here – best by waiting a little before trying again :)
            return "API limit exceeded. Please try again later.";
        case -1:
            // An error occurred
            // Deal with it here
            return "An error occurred while checking the file.";
        case 0:
            // No results (yet) – but the file is already enqueued at VirusTotal
            $scan_id = $vt->getScanId();
            $json_response = $vt->getResponse();
            return "File is enqueued at VirusTotal. Scan ID: $scan_id";
        case 1:
            // Results are available
            $json_response = $vt->getResponse();
            return "Results are available. Scan results:\n" . print_r($json_response, true);
        default:
            // You should not reach this point if you've placed the break before :)
            return "Unexpected result.";
    }
}

// Check if the form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit'])) {

    // Check if the file input is set
    if (isset($_FILES['file'])) {

        // File details
        $file_name = $_FILES['file']['name'];
        $file_tmp = $_FILES['file']['tmp_name'];
        $file_size = $_FILES['file']['size'];
        $file_type = $_FILES['file']['type'];
        $file_error = $_FILES['file']['error'];

        // Check for errors
        if ($file_error === 0) {

            // Move the uploaded file to a desired directory
            $upload_directory = 'uploads/';
            $destination = $upload_directory . $file_name;

            // Move the file
            if (move_uploaded_file($file_tmp, $destination)) {

                // Check the file with VirusTotal
                $vtResult = checkFileWithVirusTotal($destination);

                // Output the result
                echo $vtResult;

            } else {
                echo "Error uploading file.";
            }

        } else {
            echo "Error: " . $file_error;
        }

    } else {
        echo "File input not set.";
    }

} else {
    echo "Form not submitted.";
}

?>
