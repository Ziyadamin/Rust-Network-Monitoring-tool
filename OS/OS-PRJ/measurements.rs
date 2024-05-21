use std::collections::VecDeque;
use std::collections::HashMap;

use pnet::datalink::NetworkInterface;

pub type Measurement = egui::plot::PlotPoint;


pub struct MeasurementWindow {
    pub values: VecDeque<Measurement>,
    pub look_behind: usize,
    pub table_data:HashMap<String, TrafficStats>,
    pub intf:String,
    pub lim_vec:LimitedVec,
    pub sec:LimitedVec,
   // pub iface:NetworkInterface,
}
pub struct TrafficStats {
    pub download: f64,
    pub upload: f64,
}
#[derive(Debug, Clone)]
pub struct LimitedVec {
   pub vec: Vec<String>,
    capacity: usize,
}

impl LimitedVec {
    // Constructor to create a new LimitedVec with a given capacity
    pub fn new(capacity: usize) -> Self {
        LimitedVec {
            vec: Vec::with_capacity(capacity),
            capacity,
        }
    }

    // Method to push a new element
    pub fn push(&mut self, element: String) {
        if self.vec.len() == self.capacity {
            self.vec.remove(0);
        }
        self.vec.push(element);
    }

    // Method to get the current elements
    pub fn elements(&self) -> &Vec<String> {
        &self.vec
    }
}

impl TrafficStats {
    pub fn new(download: f64, upload: f64) -> Self {
        Self { download, upload }
    }
}
impl Clone for TrafficStats {
    fn clone(&self) -> Self {
        Self {
            download: self.download,
            upload: self.upload,
        }
    }
}

impl MeasurementWindow {
    pub fn new_with_look_behind(look_behind: usize) -> Self {
        Self {
            values: VecDeque::new(),
            look_behind,
            table_data: HashMap::new(),
            intf:String::new(),
            lim_vec:LimitedVec::new(60),
            sec:LimitedVec::new(60),
          // iface: NetworkInterface::
           
        }
    }
    pub fn push_data(&mut self, key: String, stats: TrafficStats) {
        self.table_data.insert(key, stats);
    }

    pub fn pop_data(&mut self, key: &str) {
        self.table_data.remove(key);
    }

    pub fn num_entries(&self) -> usize {
        self.table_data.len()
    }
    pub fn set_data(&mut self, new_data: HashMap<String, TrafficStats>) {
        self.table_data = new_data;
    }
    pub fn set_lim(&mut self, new_data:LimitedVec,secv:LimitedVec) {
        self.lim_vec = new_data;
        self.sec=secv;
    }


    pub fn add(&mut self, measurement: Measurement) {
        if let Some(last) = self.values.back() {
            if measurement.x < last.x {
                self.values.clear()
            }
        }

        self.values.push_back(measurement);

        let limit = self.values.back().unwrap().x - (self.look_behind as f64);
        while let Some(front) = self.values.front() {
            if front.x >= limit {
                break;
            }
            self.values.pop_front();
        }
    }
    
    pub fn plot_values(&self) -> egui::plot::PlotPoints {
        egui::plot::PlotPoints::Owned(Vec::from_iter(self.values.iter().copied()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_measurements() {
        let w = MeasurementWindow::new_with_look_behind(123);
        assert_eq!(w.values.len(), 0);
        assert_eq!(w.look_behind, 123);
    }

    #[test]
    fn appends_one_value() {
        let mut w = MeasurementWindow::new_with_look_behind(100);

        w.add(Measurement::new(10.0, 20.0));
        assert_eq!(
            w.values.into_iter().eq(vec![Measurement::new(10.0, 20.0)]),
            true
        );
    }

    #[test]
    fn clears_on_out_of_order() {
        let mut w = MeasurementWindow::new_with_look_behind(100);

        w.add(Measurement::new(10.0, 20.0));
        w.add(Measurement::new(20.0, 30.0));
        w.add(Measurement::new(19.0, 100.0));
        assert_eq!(
            w.values.into_iter().eq(vec![Measurement::new(19.0, 100.0)]),
            true
        );
    }

    #[test]
    fn appends_several_values() {
        let mut w = MeasurementWindow::new_with_look_behind(100);

        for x in 1..=20 {
            w.add(Measurement::new((x as f64) * 10.0, x as f64));
        }

        assert_eq!(
            w.values.into_iter().eq(vec![
                Measurement::new(10.0, 10.0),
                Measurement::new(11.0, 11.0),
                Measurement::new(12.0, 12.0),
                Measurement::new(13.0, 13.0),
                Measurement::new(14.0, 14.0),
                Measurement::new(15.0, 15.0),
                Measurement::new(16.0, 16.0),
                Measurement::new(17.0, 17.0),
                Measurement::new(18.0, 18.0),
                Measurement::new(19.0, 19.0),
                Measurement::new(20.0, 20.0),
            ]),
            true
        );
    }
}