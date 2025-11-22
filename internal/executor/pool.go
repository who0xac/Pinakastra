package executor

import (
	"context"
	"sync"
)

type WorkerPool struct {
	workers    int
	jobs       chan Job
	results    chan JobResult
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

type Job struct {
	ID      string
	Execute func() (interface{}, error)
}

type JobResult struct {
	ID     string
	Result interface{}
	Error  error
}

func NewWorkerPool(workers int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		workers: workers,
		jobs:    make(chan Job, workers*2),
		results: make(chan JobResult, workers*2),
		ctx:     ctx,
		cancel:  cancel,
	}

	pool.start()
	return pool
}

func (p *WorkerPool) start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
}

func (p *WorkerPool) worker() {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return
		case job, ok := <-p.jobs:
			if !ok {
				return
			}

			result, err := job.Execute()
			p.results <- JobResult{
				ID:     job.ID,
				Result: result,
				Error:  err,
			}
		}
	}
}

func (p *WorkerPool) Submit(job Job) {
	select {
	case <-p.ctx.Done():
		return
	case p.jobs <- job:
	}
}

func (p *WorkerPool) Results() <-chan JobResult {
	return p.results
}

func (p *WorkerPool) Stop() {
	p.cancel()
	close(p.jobs)
	p.wg.Wait()
	close(p.results)
}
