/*
 * Model1.cpp
 * Project:   AppFastLane
 * Author:    raymond@burkholder.net
 * copyright: 2019 Raymond Burkholder
 * License:   GPL3
 * Created on: Aug. 19, 2019
 */

#include <Wt/WDateTime.h>

#include "Model1.h"

Model1::Model1()
{
  Wt::WAbstractItemModel::rowsAboutToBeInserted().connect(
    []( Wt::WModelIndex, int rowFirst, int rowLast ){
      std::cout << "rowsAboutToBeInserted: " << rowFirst << "," << rowLast << std::endl;
    } );
  Wt::WAbstractItemModel::rowsInserted ().connect(
    []( Wt::WModelIndex, int rowFirst, int rowLast ){
      std::cout << "rowsInserted: " << rowFirst << "," << rowLast << std::endl;
    } );
}

Model1::~Model1() {
}

int Model1::columnCount(const Wt::WModelIndex &parent ) const {
  //std::cout << "Model1::columnCount" << std::endl;
  return 1;
}

int Model1::rowCount(const Wt::WModelIndex &parent ) const {
  //std::cout << "Model1::rowCount: " << m_vData.size() << std::endl;
  return m_vData.size();
}

Wt::WModelIndex Model1::parent(const Wt::WModelIndex &index) const {
  //std::cout << "Model1::parent" << std::endl;
  return createIndex( index.row(), index.column(), nullptr );
}

std::any Model1::data(const Wt::WModelIndex &index, Wt::ItemDataRole role ) const {
  switch ( role.value() ) {
    case Wt::ItemDataRole::ToolTip:
    case Wt::ItemDataRole::MarkerType:
    case Wt::ItemDataRole::MarkerPenColor:
    case Wt::ItemDataRole::MarkerBrushColor:
    case Wt::ItemDataRole::MarkerScaleFactor:
      return std::any();
      break;
    case Wt::ItemDataRole::Display:
      return m_vData[ index.row() ].any[ index.column() ];
      break;
    default:
      std::cout
        << "Model1::data: "
        << "role=" << role.value()
        << ",row=" << index.row()
        << ",col=" << index.column()
        << "," << m_vData[ index.row() ].any[ index.column() ].has_value()
        << "," << m_vData[ index.row() ].any[ index.column() ].type().name()
        << ",";
      if ( 0 == index.column() ) std::cout << std::any_cast<Wt::WDateTime>( m_vData[ index.row() ].any[ index.column() ] ).toString();
      else std::cout << std::any_cast<long long>( m_vData[ index.row() ].any[ index.column() ] );
      std::cout << std::endl;
      break;
  }
  return std::any();
}

Wt::WModelIndex Model1::index(int row, int column, const Wt::WModelIndex &parent ) const {
  //std::cout << "Model1::index: " << row << "," << column << std::endl;
  return createIndex( row, column, nullptr );
}

std::any Model1::headerData(int section, Wt::Orientation orientation, Wt::ItemDataRole role ) const {
  switch ( role.value() ) {
    case Wt::ItemDataRole::Display:
      break;
    default:
      std::cout
        << "Model1::headerData: "
        << "section=" << section
        << ",role=" << role.value()
        << std::endl;
      break;
  }
  return std::any();
}

Wt::WFlags<Wt::ItemFlag> Model1::flags(const Wt::WModelIndex &index) const {
  std::cout << "Model1::flags:" << index.row() << "," << index.column() << std::endl;
  return Wt::WAbstractItemModel::flags( index );
}

bool Model1::insertRows (int row, int count, const Wt::WModelIndex &parent ) {
  beginInsertRows( parent, row, row + count - 1 );
  //std::cout << "Model1::insertRows: " << row << "," << count <<  std::endl;
  m_vData.resize( m_vData.size() + count );
  endInsertRows();
  //return Wt::WAbstractItemModel::insertRows( row, count, parent );
  return true;
}

bool Model1::setData(const Wt::WModelIndex &index, const std::any &value, Wt::ItemDataRole role ) {
  //std::cout
  //  << "Model1::setData: "
  //  << index.row()
  //  << "," << index.column()
    //<< "," << role
  //  << std::endl;
  m_vData[ index.row() ].any[ index.column() ] = value;
  Wt::WAbstractItemModel::dataChanged().emit( index, index );
  return true;
}

bool Model1::hasChildren(const Wt::WModelIndex &index) const {
  std::cout << "Model1::hasChildren: " << index.row() << "," << index.column() <<  std::endl;
  return true;
}

Wt::WAbstractItemModel::DataMap Model1::itemData (const Wt::WModelIndex &index) const {
  std::cout << "Model1::itemData: " << index.row() << "," << index.column() <<  std::endl;
  return Wt::WAbstractItemModel::DataMap();
}

bool Model1::hasIndex(int row, int column, const Wt::WModelIndex &parent ) const {
  std::cout << "Model1::hasIndex: " << row << "," << column <<  std::endl;
  return false;
}
