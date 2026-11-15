package rate

import (
	"context"
	"time"

	"github.com/juju/ratelimit"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type BucketGetter func() *ratelimit.Bucket

func waitTokens(ctx context.Context, get BucketGetter, n int) error {
	if get == nil || n <= 0 {
		return nil
	}
	b := get()
	if b == nil {
		return nil
	}
	d := b.Take(int64(n))
	if d <= 0 {
		return nil
	}
	if ctx == nil {
		time.Sleep(d)
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type Writer struct {
	ctx    context.Context
	writer buf.Writer
	get    BucketGetter
}

func NewRateLimitWriter(writer buf.Writer, limiter *ratelimit.Bucket) buf.Writer {
	return NewDynamicRateLimitWriter(nil, writer, func() *ratelimit.Bucket { return limiter })
}

func NewDynamicRateLimitWriter(ctx context.Context, writer buf.Writer, get BucketGetter) buf.Writer {
	return &Writer{
		ctx:    ctx,
		writer: writer,
		get:    get,
	}
}

func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) Interrupt() {
	common.Interrupt(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := waitTokens(w.ctx, w.get, int(mb.Len())); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	return w.writer.WriteMultiBuffer(mb)
}

var _ buf.TimeoutReader = (*Reader)(nil)

type Reader struct {
	ctx    context.Context
	reader buf.TimeoutReader
	get    BucketGetter
}

func NewDynamicRateLimitReader(ctx context.Context, reader buf.TimeoutReader, get BucketGetter) buf.TimeoutReader {
	return &Reader{
		ctx:    ctx,
		reader: reader,
		get:    get,
	}
}

func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if err != nil {
		return nil, err
	}
	if err := waitTokens(r.ctx, r.get, int(mb.Len())); err != nil {
		buf.ReleaseMulti(mb)
		return nil, err
	}
	return mb, nil
}

func (r *Reader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBufferTimeout(timeout)
	if err != nil {
		return nil, err
	}
	if err := waitTokens(r.ctx, r.get, int(mb.Len())); err != nil {
		buf.ReleaseMulti(mb)
		return nil, err
	}
	return mb, nil
}

func (r *Reader) Interrupt() {
	common.Interrupt(r.reader)
}

func (r *Reader) Close() error {
	return common.Close(r.reader)
}
