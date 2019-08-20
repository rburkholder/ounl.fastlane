/*
 * Model1.h
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created on: Aug. 19, 2019
 */

#ifndef APPFASTLANE_MODEL1_H_
#define APPFASTLANE_MODEL1_H_

#include <Wt/WAbstractItemModel.h>

class Model1: public Wt::WAbstractItemModel {
public:
  Model1();
  ~Model1();

  virtual int columnCount(const Wt::WModelIndex &parent=Wt::WModelIndex() ) const;
  virtual int rowCount(const Wt::WModelIndex &parent=Wt::WModelIndex() ) const;
  virtual Wt::WModelIndex parent(const Wt::WModelIndex &index) const;
  virtual std::any data(const Wt::WModelIndex &index, Wt::ItemDataRole role=Wt::ItemDataRole::Display ) const;
  virtual Wt::WModelIndex index(int row, int column, const Wt::WModelIndex &parent=Wt::WModelIndex()) const;
  virtual std::any headerData(int section, Wt::Orientation orientation=Wt::Orientation::Horizontal, Wt::ItemDataRole role=Wt::ItemDataRole::Display) const;
  virtual Wt::WFlags< Wt::ItemFlag > flags(const Wt::WModelIndex &index) const;

  virtual bool insertRows(int row, int count, const Wt::WModelIndex &parent=Wt::WModelIndex() );
  //bool setData (int row, int column, const Wt::cpp17::any &value, Wt::ItemDataRole role=Wt::ItemDataRole::Edit, const Wt::WModelIndex &parent=Wt::WModelIndex() );
  virtual bool setData(const Wt::WModelIndex &index, const Wt::cpp17::any &value, Wt::ItemDataRole role=Wt::ItemDataRole::Edit );
  virtual bool hasChildren(const Wt::WModelIndex &index) const;
protected:
private:

  struct Data {
    std::any any[ 4 ];
  };
  std::vector<Data> m_vData;
};

#endif /* APPFASTLANE_MODEL1_H_ */



