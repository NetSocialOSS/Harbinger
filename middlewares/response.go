package middlewares

import (
	"github.com/gofiber/fiber/v2"
)

// ErrorResponse represents a standardized error response structure.
type ErrorResponse struct {
	Success bool        `json:"success"`
	Error   string      `json:"error"`
	Data    interface{} `json:"data,omitempty"`
}

// NewError creates a standardized error response.
// It accepts an error message and optional data to provide additional context.
func NewError(msg string, data ...interface{}) *ErrorResponse {
	errResponse := &ErrorResponse{
		Success: false,
		Error:   msg,
	}
	if len(data) > 0 {
		errResponse.Data = data
	}
	return errResponse
}

// SuccessResponse represents a standardized success response structure.
type SuccessResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// NewSuccess creates a standardized success response.
// It accepts a success message and optional data as the payload.
func NewSuccess(msg string, data ...interface{}) *SuccessResponse {
	successResponse := &SuccessResponse{
		Success: true,
		Message: msg,
	}
	if len(data) == 1 {
		successResponse.Data = data[0] // If there's exactly one data item, include it directly.
	} else if len(data) > 1 {
		successResponse.Data = data // If there are multiple data items, include them as an array.
	}
	return successResponse
}

// SendErrorResponse sends a standardized error response.
func SendErrorResponse(c *fiber.Ctx, statusCode int, err *ErrorResponse) error {
	return c.Status(statusCode).JSON(err)
}

// SendSuccessResponse sends a standardized success response.
func SendSuccessResponse(c *fiber.Ctx, statusCode int, success *SuccessResponse) error {
	return c.Status(statusCode).JSON(success)
}
