package loadingBar

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sync/semaphore"
	"golang.org/x/term"
	"math"
	"sync"
	"time"
)

// LoadingBar is a structure which holds all components to provide the loading bar.
//
//	currentStatusChans	[]chan int			- the channels via which functions can report the current status
//	maxStatuses       	[]int				- thw maximum capacity of each channel
//	getChanSemaphore  	*semaphore.Weighted	- a semaphore controlling parallel access on the channels
//	chansToAcquire    	[]chan int			- channels which aren't already used to report a status
//	stopLoadingBar     	bool				- true if the loading bar shouldn't be shown anymore
//	loadingBarStopped  	bool				- true if the loading bar isn't shown anymore
type LoadingBar struct {
	currentStatusChans []chan int
	maxStatuses        []int
	getChanSemaphore   *semaphore.Weighted
	chansToAcquire     []chan int
	stopLoadingBar     bool
	loadingBarStopped  sync.WaitGroup
}

// InitLoadingBar is a constructor for the LoadingBar structure.
//
// Takes:
//	numberOfStatuses 	int		- the number of status channels needed for the loading bar
//								  one status channel is needed for each part of the program that should report
//								  to the same loading bar
//	maxInitStatuses		...int	- the size of each status channel, should accommodate the number of values reported
//								  to the channel, so it won't block
//
// Returns:
//	loadingBar	*LoadingBar	- a pointer to the created LoadingBar struct
func InitLoadingBar(numberOfStatuses int, maxInitStatuses ...int) (loadingBar *LoadingBar) {
	loadingBar = &LoadingBar{
		currentStatusChans: make([]chan int, numberOfStatuses),
		maxStatuses:        maxInitStatuses,
		getChanSemaphore:   semaphore.NewWeighted(1),
		chansToAcquire:     make([]chan int, numberOfStatuses),
		stopLoadingBar:     false,
		loadingBarStopped:  sync.WaitGroup{},
	}

	// init each chan with the correct size and add it to the acquirable channels
	for i := 0; i < len(loadingBar.currentStatusChans); i++ {
		loadingBar.currentStatusChans[i] = make(chan int, loadingBar.maxStatuses[i])
		loadingBar.chansToAcquire[i] = loadingBar.currentStatusChans[i]
	}

	// Loading bar hasn't stopped let everybody wait
	loadingBar.loadingBarStopped.Add(1)

	return
}

// GetStatusChanWithCapacity is a public function which provide an acquirable channel with a given capacity.
// Provide integers that are counting up after RunLoadingBar was called to let the loading bar count up.
//
// Operates on:
//	loadingBar	*LoadingBar	- a pointer to the LoadingBar structure which provides the channels
//
// Takes:
//	capacity	int	- the capacity the channel should have
//
// Returns:
//	currentStatusChan	chan int	- the channel requested, nil if an error occurred
//	err 				error		- the error if no channel could be acquired
func (loadingBar *LoadingBar) GetStatusChanWithCapacity(capacity int) (currentStatusChan chan int, err error) {
	err = loadingBar.getChanSemaphore.Acquire(context.Background(), 1) // get the semaphore to acquire a channel
	if err != nil {
		return nil, err
	} // shouldn't happen because the acquiring of the semaphore will wait in the background

	currentStatusChan = nil

	// try to acquire a chan with the requested capacity
	for i, freeChan := range loadingBar.chansToAcquire {
		if cap(freeChan) == capacity {
			currentStatusChan = freeChan
			loadingBar.chansToAcquire = append(loadingBar.chansToAcquire[:i], loadingBar.chansToAcquire[i+1:]...)
			break
		}
	}

	// error if no channel was found
	if currentStatusChan == nil {
		err = errors.New("there is no chan with the given capacity")
	} else {
		err = nil
	}

	// release the semaphore
	loadingBar.getChanSemaphore.Release(1)

	return
}

// RunLoadingBar is a public function to run and display the loading bar.
//
// Operates on:
//	loadingBar	*LoadingBar	- a pointer to the loading bar that should be displayed
func (loadingBar *LoadingBar) RunLoadingBar() {
	// get the terminal width
	width, _, err := term.GetSize(0)
	if err != nil {
		// ignore / no loading bar will run
		loadingBar.loadingBarStopped.Done()
		return
	}

	// make a slice to store the current status
	currentStatuses := make([]int, len(loadingBar.currentStatusChans))

	// the maximum number that could be the current status
	maxStatusesSum := 0
	for _, maxStatus := range loadingBar.maxStatuses {
		maxStatusesSum += maxStatus
	}

	// read asynchronous the values from the channels and provide them to the currentStatuses slice
	for i, statusChan := range loadingBar.currentStatusChans {
		go func(currentStatus *int, statusChan chan int) {
			for readFrom := range statusChan {
				*currentStatus = readFrom
			}
		}(&currentStatuses[i], statusChan)
	}

	// display the loading bar, non blocking
	go func() {
		currentStatusesSum := 0
		blinkOn := true

		for currentStatusesSum < maxStatusesSum {
			if loadingBar.stopLoadingBar {
				// the loading bar should stop, break the loop
				break
			}

			// calculate the current status
			currentStatusesSum = 0
			for _, currentStatus := range currentStatuses {
				currentStatusesSum += currentStatus
			}

			// printing of the loading bar
			fmt.Print("\r")
			for i := 0; i < width; i++ {
				fmt.Print(" ")
			}
			fmt.Print("\r")
			currentStatus := float64(currentStatusesSum) / float64(maxStatusesSum)
			currentStatusPercent := currentStatus * 100

			currentLoadingBar := math.Floor(currentStatusPercent) / 2

			currentStatusPercent = math.Round(currentStatusPercent*1000) / 1000

			fmt.Print("<")
			for i := 0; i < int(currentLoadingBar); i++ {
				fmt.Print("=")
			}
			if blinkOn && currentLoadingBar < 50 {
				fmt.Print(">")
				for i := 0; i < 49-int(currentLoadingBar); i++ {
					fmt.Print(" ")
				}
				blinkOn = false
			} else {
				for i := 0; i < 50-int(currentLoadingBar); i++ {
					fmt.Print(" ")
				}
				blinkOn = true
			}

			fmt.Print("> ")
			if currentStatusPercent < 10 {
				fmt.Print("  ", currentStatusPercent, " %")
			} else if currentStatusPercent < 100 {
				fmt.Print(" ", currentStatusPercent, " %")
			} else {
				fmt.Print(currentStatusPercent, " %")
			}

			timer := time.NewTimer(250 * time.Millisecond)
			<-timer.C
		}

		// loop broken loading bar has stopped
		loadingBar.loadingBarStopped.Done()
	}()
}

// StopLoadingBar is a public function to stop the loading bar and erase it from the screen.
//
// Operates on:
//	loadingBar	*LoadingBar	- a pointer to the loading bar that should be stopped
func (loadingBar *LoadingBar) StopLoadingBar() {
	loadingBar.stopLoadingBar = true    // provide the running loading bar with the information to stop
	loadingBar.loadingBarStopped.Wait() // wait for the loading bar to stop

	// clear the screen
	fmt.Print("\r")
	width, _, err := term.GetSize(1) // get the terminal width
	if err != nil {
		// set default terminal width
		width = 80
	}
	for i := 0; i < width; i++ {
		fmt.Print(" ")
	}
	fmt.Print("\r")
}
