package tracer

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

func InitTracer(ctx context.Context, servicename string, otlpEndpoint string)( func(context.Context) error, error ){
	if(otlpEndpoint == ""){
		otlpEndpoint = "localhost:4317"
	}

	exporter, err := otlptracegrpc.New( ctx,
						otlptracegrpc.WithEndpoint(otlpEndpoint),
						otlptracegrpc.WithInsecure(),
						otlptracegrpc.WithTimeout(5*time.Second),
	)

	if err != nil {
		return nil, fmt.Errorf("Failed to create OTLP Trace Exporter: %w", err)
	}

	res, err := resource.New(ctx,
					resource.WithAttributes(
						semconv.ServiceNameKey.String(servicename),
					),
	)

	if err != nil {
		return nil, fmt.Errorf("Failed to create resource: %w", err)
	}

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}