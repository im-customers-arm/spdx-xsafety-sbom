/**
 * Sample source file with @sdoc markers for testing.
 */

#include "cam_service.h"

// @sdoc[SSR-001]
void schedule_timeout_timer(cam_event_t *event) {
    timer_t timer = create_timer(1000);  // 1000ms timeout
    timer_set_callback(timer, on_timeout_violation);
    timer_start(timer);
    event->timer = timer;
}

// @sdoc[SSR-002]
void cancel_timeout_timer(cam_event_t *event) {
    if (event->timer != NULL) {
        timer_stop(event->timer);
        timer_destroy(event->timer);
        event->timer = NULL;
    }
}

// @sdoc[SSR-001, SSR-002]
void handle_cam_event(cam_event_t *event) {
    // Cancel existing timer
    cancel_timeout_timer(event);
    
    // Process the event
    process_event(event);
    
    // Schedule new timer for next expected event
    schedule_timeout_timer(event);
}
